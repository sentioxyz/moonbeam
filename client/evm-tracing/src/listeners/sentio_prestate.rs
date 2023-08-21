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

use std::collections::BTreeMap;
use ethereum_types::{H160, H256};
use evm_tracing_events::{Event, EvmEvent, Listener as ListenerT, RuntimeEvent, StepEventFilter};
use crate::types::sentio::{State, SentioPrestateTrace, SentioPrestateTracerConfig, Account};
use std::{future::Future, marker::PhantomData, sync::Arc};
use std::ptr::null;
use fp_rpc::EthereumRuntimeRPCApi;
use sp_api::{ApiExt, ApiRef, BlockId, Core, HeaderT, ProvideRuntimeApi};
use sp_runtime::traits::{BlakeTwo256, Block as BlockT, UniqueSaturatedInto};

pub struct Listener<B, C>
	where
		B: BlockT,
		C:ProvideRuntimeApi<B>,
		C::Api: EthereumRuntimeRPCApi<B>,
{
	pub results: Vec<SentioPrestateTrace>,

	config: SentioPrestateTracerConfig,
	gas_limit: u64,
	pre: State,
	post: State,
	create: bool,
	to: H160,
	created: BTreeMap<H160, bool>,
	deleted: BTreeMap<H160, bool>,
	mapping_keys: BTreeMap<String, String>,

	call_list_first_transaction: bool,

	_b: PhantomData<B>,
	block: B::Hash,
	client: Arc<C>,
	// api: use std::{future::Future, marker::PhantomData, sync::Arc};
	// client: Arc<C>,
}

impl<B, C> Listener<B, C>
	where
		B: BlockT,
		C:ProvideRuntimeApi<B>  + 'static,
		C::Api: EthereumRuntimeRPCApi<B>,
{
	pub fn new(config: SentioPrestateTracerConfig, block: B::Hash, client: &Arc<C>) -> Self {
		Self {
			results: vec![],
			config,
			gas_limit: 0,
			pre: Default::default(),
			post: Default::default(),
			create: false,
			to: Default::default(),
			created: Default::default(),
			deleted: Default::default(),
			mapping_keys: Default::default(),
			call_list_first_transaction: false,
			_b: Default::default(),
			block,
			client: Arc::clone(client)
		}
	}

	pub fn using<R, F: FnOnce() -> R>(&mut self, f: F) -> R {
		evm_tracing_events::using(self, f)
	}

	pub fn finish_transaction(&mut self) {}

	pub fn evm_event(&mut self, event: EvmEvent) {
		// self.client.verify_truncated_right()
		match event {
			EvmEvent::TransactCall { gas_limit,caller, address,  .. }
			| EvmEvent::TransactCreate { gas_limit,caller, address,  .. }
			| EvmEvent::TransactCreate2 { gas_limit,caller, address,  .. } => {
				self.gas_limit = gas_limit;

				self.lookup_account(caller);
				self.lookup_account(address);
				// self.lookup_account(self.client.runtime_api())
			}
			_ => {}
		}
	}

	pub fn runtime_event(&mut self, event: RuntimeEvent) { }

	// lookupAccount fetches details of an account and adds it to the prestate
	// if it doesn't exist there.
	fn lookup_account(&mut self, address: H160) {
		if self.pre.contains_key(&address) {
			return;
		}
		let api = self.client.runtime_api();
		let basic = api.account_basic(self.block, address).ok();
		let code = api.account_code_at(self.block, address).ok();
		let account: Account = Account {
			balance: basic.clone().map(|b| b.balance),
			nonce: basic.map(|b| b.nonce).unwrap_or_default(),
			code,
			storage: Default::default(),
			code_address: None,
		};
		self.pre.insert(address, account);
	}
}

impl<B, C> ListenerT for Listener<B, C>
	where
		B: BlockT,
		C:ProvideRuntimeApi<B>  + 'static,
		C::Api: EthereumRuntimeRPCApi<B> {
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
			enable_memory: false,
			enable_stack: false,
		}
	}
}
