// Copyright 2019-2022 PureStake Inc.
// This file is part of Moonbeam.

// Moonbeam is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Moonbeam is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Moonbeam.  If not, see <http://www.gnu.org/licenses/>.

use std::collections::BTreeSet;
use ethereum_types::{BigEndianHash, H160, H256, U256};
use evm_tracing_events::{Event, EvmEvent, Listener as ListenerT, RuntimeEvent, StepEventFilter};
use evm_tracing_events::runtime::{Memory, Opcode, Stack};
use std::ops::Deref;
use fp_rpc::EthereumRuntimeRPCApi;
use sha3::{Digest, Keccak256};
use sp_api::{ApiRef, ProvideRuntimeApi};
use sp_block_builder::BlockBuilder;
use sp_runtime::traits::Block as BlockT;
use rlp::RlpStream;

use crate::listeners::sentio_util::{copy_memory, stack_back, to_opcode};
use crate::types::sentio::{State, SentioPrestateTrace, SentioPrestateTracerConfig, Account};

#[derive(Debug, Clone)]
struct Step {
	/// Current opcode.
	opcode: Opcode,
	memory: Memory,
	stack: Stack,
}

#[derive(Debug)]
struct Context {
	address: H160,
	code_address: Option<H160>,
	current_step: Option<Step>,
	current_opcode: Option<String>,
}

pub struct Listener<B, C>
	where
		B: BlockT,
		C: ProvideRuntimeApi<B> + 'static,
		C::Api: EthereumRuntimeRPCApi<B>,
		C::Api: BlockBuilder<B>,
{
	pub results: Vec<SentioPrestateTrace>,

	tracer_config: SentioPrestateTracerConfig,
	gas_limit: u64,
	pre: State,
	post: State,
	create: bool,
	created: BTreeSet<H160>,
	deleted: BTreeSet<H160>,

	context_stack: Vec<Context>,

	api: *const C::Api,
	beneficiary: H160,
	extrinsics: Vec<B::Extrinsic>,
	parent_block: B::Hash,

	call_list_first_transaction: bool,
}

impl<B, C> Listener<B, C>
	where
		B: BlockT,
		C: ProvideRuntimeApi<B>,
		C::Api: EthereumRuntimeRPCApi<B>,
		C::Api: BlockBuilder<B>,
{
	pub fn new(config: SentioPrestateTracerConfig, parent_block: B::Hash, extrinsics: Vec<B::Extrinsic>, beneficiary: H160, api: &ApiRef<C::Api>) -> Self {
		Self {
			results: vec![],
			tracer_config: config,
			gas_limit: 0,
			pre: Default::default(),
			post: Default::default(),
			create: false,
			created: Default::default(),
			deleted: Default::default(),
			call_list_first_transaction: false,
			parent_block,
			extrinsics,
			api: api.deref(),
			beneficiary,
			context_stack: vec![],
		}
	}

	pub fn using<R, F: FnOnce() -> R>(&mut self, f: F) -> R {
		evm_tracing_events::using(self, f)
	}

	pub fn finish_transaction(&mut self) {
		let last_extrinsic = self.extrinsics.pop().expect("has last");

		if self.tracer_config.diff_mode {
			let api = unsafe { &*self.api };
			let _ = api.apply_extrinsic(self.parent_block, last_extrinsic);

			let mut pre_to_be_deleted: Vec<H160> = vec![];
			// if t.create { // probably don't need in this impl
			// 	// Keep existing account prior to contract creation at that address
			// 	if s := t.pre[t.to]; s != nil && !s.exists() {
			// 		// Exclude newly created contract.
			// 		delete(t.pre, t.to)
			// 	}
			// }
			for (addr, pre_account) in self.pre.iter_mut() {
				let addr = *addr;
				// The deleted account's state is pruned from `post` but kept in `pre`
				if self.deleted.contains(&addr) {
					continue;
				}
				let mut modified = false;
				let basic = api.account_basic(self.parent_block, addr).ok();

				let mut post_account = Account {
					balance: None,
					code: vec![],
					nonce: None,
					storage: Default::default(),
					code_address: None,
					mapping_keys: Default::default(),
				};
				let new_balance = basic.clone().map(|x| x.balance);
				let new_nonce = basic.map(|x| x.nonce);
				let new_code = api.account_code_at(self.parent_block, addr).unwrap_or_default();

				if new_balance != pre_account.balance {
					modified = true;
					post_account.balance = new_balance;
				}

				if new_nonce != pre_account.nonce {
					modified = true;
					post_account.nonce = new_nonce;
				}

				if new_code != pre_account.code {
					modified = true;
					post_account.code = new_code;
				}

				let mut to_be_removed: Vec<H256> = vec![];
				for (key, val) in &pre_account.storage {
					// don't include the empty slot
					if *val == H256::default() {
						to_be_removed.push(*key);
					}

					let new_val = api.storage_at(self.parent_block, addr, key.into_uint()).expect("has storage value");
					if *val == new_val {
						to_be_removed.push(*key);
					} else {
						modified = true;
						if new_val != H256::zero() {
							post_account.storage.insert(*key, new_val);
						}
					}
				}
				for key in to_be_removed {
					pre_account.storage.remove(&key);
				}

				if modified {
					self.post.insert(addr, post_account);
				} else {
					// if state is not modified, then no need to include into the pre state
					pre_to_be_deleted.push(addr)
				}
			}

			// the new created contracts' prestate were empty, so delete them
			for a in &self.created {
				// the created contract maybe exists in statedb before the creating tx
				let s = self.pre.get(&a);
				if let Some(s) = s {
					if !account_existed(s) {
						pre_to_be_deleted.push(*a)
					}
				}
			}

			for addr in pre_to_be_deleted {
				self.pre.remove(&addr);
			}
		}

		let mut res = SentioPrestateTrace {
			pre: Default::default(),
			post: Default::default(),
		};

		core::mem::swap(&mut res.pre, &mut self.pre);
		core::mem::swap(&mut res.post, &mut self.post);
		self.created.clear();
		self.deleted.clear();
		self.gas_limit = 0;
		self.create = false;
		self.results.push(res);
	}

	fn push_stack(&mut self, address: H160, code_address: Option<H160>) {
		self.context_stack.push(Context {
			address: address,
			code_address: code_address,
			current_step: None,
			current_opcode: None,
		});
	}

	pub fn evm_event(&mut self, event: EvmEvent) {
		match &event {
			EvmEvent::TransactCreate { gas_limit, caller, address, .. } |
			EvmEvent::TransactCreate2 { gas_limit, caller, address, .. } |
			EvmEvent::TransactCall { gas_limit, caller, address, .. } => {
				let mut exts: Vec<B::Extrinsic> = vec![];
				core::mem::swap(&mut exts, &mut self.extrinsics);
				exts.pop().map(|ext| self.extrinsics.push(ext));
				let api = unsafe { &*self.api };
				for e in exts {
					let _ = api.apply_extrinsic(self.parent_block, e);
				}

				self.gas_limit = *gas_limit;
				self.lookup_account(*caller);
				self.lookup_account(*address);
				self.lookup_account(self.beneficiary);
			}
			_ => {}
		}

		match &event {
			EvmEvent::TransactCreate { address, .. }
			| EvmEvent::TransactCreate2 { address, .. } => {
				self.create = true;
				if self.tracer_config.diff_mode {
					self.created.insert(*address);
				}
			}
			_ => {}
		}

		match &event {
			EvmEvent::TransactCreate { address, .. } |
			EvmEvent::TransactCreate2 { address, .. } |
			EvmEvent::TransactCall { address, .. } |
			EvmEvent::Create { address, .. } |
			EvmEvent::Suicide { address, .. } => {
				self.push_stack(*address, None);
			}
			EvmEvent::Call { code_address, context, .. } |
			EvmEvent::PrecompileSubcall { code_address, context, .. } => {
				self.push_stack(context.address, Some(*code_address));
			}
			EvmEvent::Exit { .. } => {
				self.context_stack.pop();
			}
		}
	}

	pub fn runtime_event(&mut self, event: RuntimeEvent) {
		match event {
			RuntimeEvent::Step { opcode, stack, memory, .. } => {
				let op = to_opcode(&opcode);
				if let Some(context) = self.context_stack.last_mut() {
					if self.tracer_config.debug {
						let op_string = std::str::from_utf8(&opcode).unwrap();
						context.current_opcode = Some(op_string.to_string());
					}
					context.current_step = Some(Step {
						opcode: op,
						memory: memory.expect("memory data to not be filtered out"),
						stack: stack.expect("stack data to not be filtered out"),
					});
				}
			}
			RuntimeEvent::StepResult { .. } => {
				if let Some(context) = self.context_stack.last_mut() {
					if let Some(current_step) = context.current_step.take() {
						let Step {
							opcode,
							memory,
							stack,
						} = current_step;

						let stack_size = stack.data.len();

						match opcode {
							Opcode::SHA3 if stack_size >= 2 => {
								let size = stack_back(&stack, 1).to_low_u64_be();
								if size == 64 {
									let offset = stack_back(&stack, 0).to_low_u64_be();
									let raw_key = copy_memory(&memory, offset as usize, size as usize);
									let digest = Keccak256::digest(&raw_key.as_slice());
									let hash_of_key = H256::from_slice(&digest);
									// let key = H512::from_slice(raw_key.as_slice());
									let key= format!("{}", hex::encode(raw_key));
									let account = self.pre.get_mut(&context.address).expect("account should existed");
									account.mapping_keys.insert(key, hash_of_key);
								}
							}
							Opcode::SLOAD | Opcode::SSTORE if stack_size >= 1 => {
								// panic!("duplicate sload / sstore");
							}
							Opcode::EXTCODECOPY | Opcode::EXTCODEHASH | Opcode::EXTCODESIZE | Opcode::BALANCE if stack_size >= 1 => {
								let addr_raw = stack_back(&stack, 0);
								let addr = H160::from(*addr_raw);
								self.lookup_account(addr);
							}
							Opcode::SUICIDE if stack_size >= 1 => {
								let caller = context.address; // not in new context yet
								let addr_raw = stack_back(&stack, 0);
								let addr = H160::from(*addr_raw);
								self.lookup_account(addr);
								self.deleted.insert(caller);
							}
							Opcode::DELEGATECALL | Opcode::CALL | Opcode::STATICCALL | Opcode::CALLCODE if stack_size >= 5 => {
								let addr_raw = stack_back(&stack, 1);
								let addr = H160::from(*addr_raw);
								self.lookup_account(addr);
							}
							Opcode::CREATE => {
								let caller = context.address.as_bytes().to_vec(); // not in new context yet
								let api = unsafe { &*self.api };
								let nonce = api.account_basic(self.parent_block, context.address)
									.map(|x| x.nonce)
									.unwrap_or_default();
								let mut stream = RlpStream::new();
								stream.begin_list(2);
								stream.append(&caller);
								stream.append(&nonce);
								let data = H256::from_slice(Keccak256::digest(&stream.out()).as_slice());
								let addr = H160::from(data);
								self.lookup_account(addr);
								self.created.insert(addr);
							}
							Opcode::CREATE2 if stack_size >= 4 => {
								let caller = context.address.as_bytes().to_vec(); // not in new context yet
								let offset = stack_back(&stack, 1).to_low_u64_be();
								let size = stack_back(&stack, 2).to_low_u64_be();
								let init = copy_memory(&memory, offset as usize, size as usize);
								let init_hash = Keccak256::digest(init).to_vec();
								let salt = stack_back(&stack, 3).as_bytes().to_vec();
								let mut stream = RlpStream::new();
								stream.begin_list(4);
								stream.append(&vec![0xff]);
								stream.append(&caller);
								stream.append(&salt);
								stream.append(&init_hash);
								let data = H256::from_slice(Keccak256::digest(&stream.out()).as_slice());
								let addr = H160::from(data);
								self.lookup_account(addr);
								self.created.insert(addr);
							}
							_ => {}
						}
					}
				}
			}
			RuntimeEvent::SLoad { address, index, value: _ } |
			RuntimeEvent::SStore { address, index, value: _ } => {
				if let Some(context) = self.context_stack.last_mut() {
					if let Some(account) = self.pre.get_mut(&address) {
						account.code_address = context.code_address.or(Some(context.address));
					}
					self.lookup_storage(address, index);
				}
			}
		}
	}

	// lookupAccount fetches details of an account and adds it to the prestate
	// if it doesn't exist there.
	fn lookup_account(&mut self, address: H160) {
		if self.pre.contains_key(&address) {
			return;
		}

		let api = unsafe { &*self.api };
		let basic = api.account_basic(self.parent_block, address).ok();
		let code = api.account_code_at(self.parent_block, address).unwrap_or_default();
		let account: Account = Account {
			balance: basic.clone().map(|b| b.balance),
			nonce: basic.map(|b| b.nonce),
			code,
			storage: Default::default(),
			code_address: None,
			mapping_keys: Default::default(),
		};
		self.pre.insert(address, account);
	}

	// lookupStorage fetches the requested storage slot and adds
	// it to the prestate of the given contract. It assumes `lookupAccount`
	// has been performed on the contract before.
	fn lookup_storage(&mut self, address: H160, key: H256) {
		let account = self.pre.get_mut(&address).expect("account should already be looked at");
		if account.storage.contains_key(&key) {
			return;
		}
		let api = unsafe { &*self.api };
		let value = api
			.storage_at(self.parent_block, address, key.into_uint())
			.unwrap();
		account.storage.insert(key, value);
	}
}

impl<B, C> ListenerT for Listener<B, C>
	where
		B: BlockT,
		C: ProvideRuntimeApi<B> + 'static,
		C::Api: EthereumRuntimeRPCApi<B>,
		C::Api: BlockBuilder<B>,
{
	fn event(&mut self, event: Event) {
		match event {
			Event::Runtime(runtime_event) => self.runtime_event(runtime_event),
			Event::Evm(evm_event) => self.evm_event(evm_event),
			Event::CallListNew() => {
				if !self.call_list_first_transaction {
					self.finish_transaction();
				} else {
					self.call_list_first_transaction = false;
				}
			}
			_ => {}
		};
	}

	fn step_event_filter(&self) -> StepEventFilter {
		StepEventFilter {
			enable_memory: true,
			enable_stack: true,
		}
	}
}

fn account_existed(a: &Account) -> bool {
	return a.nonce.unwrap_or_default() > U256::zero() ||
		a.storage.len() > 0 ||
		a.balance != Some(U256::zero());
}
