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

// Early transact mode:
//
// GasometerEvent::RecordTransaction
// EvmEvent::TransactCall
// GasometerEvent::RecordTransaction
//
// 	EvmEvent::Call // GasometerEvent::RecordTransaction
// 		StepResult::StaticCall
// 			EvmEvent::StaticCall
// 			EvmEvent::Exit
// 		StepResult::Exit
// 	EvmEvent::Exit
//
// Finish
//
// Precompile call will not trigger StepResult::Exit

use crate::types::sentio;
use ethereum_types::{H160, H256, U256};
use evm_tracing_events::{runtime::{Capture, ExitError, ExitReason}, Event, EvmEvent, GasometerEvent, Listener as ListenerT, RuntimeEvent, StepEventFilter};
use std::{collections::HashMap, vec, vec::Vec, str::FromStr};
use evm_tracing_events::runtime::{Memory, Opcode, Stack};
use crate::types::sentio::{SentioBaseTrace, FunctionInfo, SentioCallTrace, SentioEventTrace, SentioTrace};
use sha3::{Digest, Keccak256};

/// Enum of the different "modes" of tracer for multiple runtime versions and
/// the kind of EVM events that are emitted.
enum TracingVersion {
	/// The first event of the transaction is `EvmEvent::TransactX`. It goes along other events
	/// such as `EvmEvent::Exit`. All contexts should have clear start/end boundaries.
	EarlyTransact,
	/// Older version in which the events above didn't existed.
	/// It means that we cannot rely on those events to perform any task, and must rely only
	/// on other events.
	Legacy,
}

#[derive(Debug)]
struct Context {
	// storage_cache: BTreeMap<H256, H256>,
	address: H160,
	code_address: Option<H160>,
	current_step: Option<Step>,
	current_opcode: Option<String>,
	// Only for debug
	gas: u64,
	start_gas: u64,
	// global_storage_changes: BTreeMap<H160, BTreeMap<H256, H256>>,
}

impl Context {
	fn used_gas(&self) -> u64 {
		self.start_gas - self.gas
	}
}

#[derive(Debug, Clone)]
struct Step {
	/// Current opcode.
	opcode: Vec<u8>,
	/// Gas cost of the following opcode.
	gas_cost: u64,
	/// Program counter position.
	pc: u64,

	memory: Memory,
	stack: Stack,
}

pub struct Listener {
	pub results: Vec<SentioCallTrace>,

	tracer_config: sentio::SentioTracerConfig,
	function_map: HashMap<H160, HashMap<u64, sentio::FunctionInfo>>,
	call_map: HashMap<H160, HashMap<u64, bool>>,
	entry_pc: HashMap<u64, bool>,

	previous_jump: Option<SentioCallTrace>,
	index: i32,

	call_stack: Vec<SentioCallTrace>,
	// can only be call trace or internal trace
	context_stack: Vec<Context>,

	call_list_first_transaction: bool,

	// precompile_address: HashSet<H160>,
	/// Version of the tracing. Not sure if we need in our tracer
	/// Defaults to legacy, and switch to a more modern version if recently added events are
	/// received.
	version: TracingVersion,
}

impl Listener {
	pub fn new(config: sentio::SentioTracerConfig) -> Self {
		let mut function_map: HashMap<H160, HashMap<u64, FunctionInfo>> = Default::default();
		let mut call_map: HashMap<H160, HashMap<u64, bool>> = Default::default();

		for (address_string, functions) in &config.functions {
			let address = H160::from_str(&address_string).unwrap();
			let mut m: HashMap<u64, FunctionInfo> = Default::default();

			for function in functions {
				let mut  new_func = function.clone();
				new_func.address = address;
				m.insert(function.pc, new_func);
			}
			function_map.insert(address, m);
		}

		for (address_string, calls) in &config.calls {
			let address = H160::from_str(&address_string).unwrap();
			let mut m: HashMap<u64, bool> = Default::default();
			for call in calls {
				m.insert(*call, true);
			}
			call_map.insert(address, m);
		}
		log::info!("create sentioTracer with {} functions and {} calls", function_map.len(), call_map.len());

		Self {
			results: vec![],
			tracer_config: config,
			function_map,
			call_map,
			previous_jump: None,
			index: 0,
			entry_pc: Default::default(),
			call_stack: vec![],
			context_stack: vec![],
			call_list_first_transaction: false,
			version: TracingVersion::Legacy,
			// https://docs.moonbeam.network/builders/pallets-precompiles/precompiles/overview/
			// precompile_address:  (1..=4095).into_iter().map(H160::from_low_u64_be).collect()
		}
	}
}

impl Listener {
	pub fn using<R, F: FnOnce() -> R>(&mut self, f: F) -> R {
		evm_tracing_events::using(self, f)
	}

	pub fn finish_transaction(&mut self) {
		self.context_stack = vec![];

		match self.version {
			TracingVersion::Legacy => {
				log::error!("legacy mode is not handle well");
			}
			_ => {}
		}

		if self.call_stack.len() != 1 {
			panic!("call stack size is not 1, {}", self.call_stack.len());
		}
		if self.context_stack.len() != 0 {
			panic!("context stack size is not 0 {}", self.context_stack.len());
		}

		let mut root = self.call_stack.remove(0);

		if root.base.start_index == -1 {
			root.base.start_index = 0;
		}

		if self.tracer_config.debug {
			root.base.tracer_config = Some(serde_json::to_vec(&self.tracer_config).unwrap_or_default());
		}
		self.results.push(root);

		self.index = 0;
		self.previous_jump = None;
	}

	// almost identical to raw
	pub fn gasometer_event(&mut self, event: GasometerEvent) {
		match event {
			GasometerEvent::RecordCost { cost, snapshot }
			| GasometerEvent::RecordDynamicCost {
				gas_cost: cost, snapshot, ..
			} => {
				let is_root = self.context_stack.len() == 1;
				if let Some(context) = self.context_stack.last_mut() {
					// Register opcode cost. (ignore costs not between Step and StepResult)
					if let Some(step) = &mut context.current_step {
						step.gas_cost = cost;
					}
					if context.start_gas == 0 {
						context.start_gas = snapshot.gas();
						if is_root {
							self.call_stack[0].base.gas = context.start_gas;
						}
					}
					context.gas = snapshot.gas();
				}
			}
			// TODO check why using this break result
			// GasometerEvent::RecordStipend { stipend, snapshot } => {
			// 	if let Some(context) = self.context_stack.last_mut() {
			// 		let gas = snapshot.gas();
			// 		log::warn!("stipend {}, {} found, not battle tested", stipend, gas);
			// 		context.gas = gas;
			// 	}
			// }
			// GasometerEvent::RecordTransaction { cost, snapshot } => {
			// 	if let Some(call) = self.call_stack.last_mut() {
			// 		call.base.gas_used = cost;
			// 	}
			// }
			// We ignore other kinds of message if any (new ones may be added in the future).
			#[allow(unreachable_patterns)]
			_ => (),
		}
	}

	pub fn runtime_event(&mut self, event: RuntimeEvent) {
		match event {
			RuntimeEvent::Step { context, opcode, position, stack, memory } => {
				let op = to_opcode(&opcode);
				match op {
					Opcode::CREATE | Opcode::CREATE2 | Opcode::CALL | Opcode::CALLCODE | Opcode::DELEGATECALL | Opcode::STATICCALL | Opcode::SUICIDE => {
						self.context_stack.push(Context {
							address: H160::zero(),
							code_address: None,
							current_step: None,
							current_opcode: None,
							gas: 0,
							start_gas: 0,
						});
					}
					_ => ()
				}

				// Ignore steps outside of any context (shouldn't even be possible).
				if let Some(context) = self.context_stack.last_mut() {
					context.current_step = Some(Step {
						opcode,
						gas_cost: 0,  // 0 for now, will add with gas events (for all)
						pc: *position.as_ref().unwrap_or(&0),
						// TODO check if this safe or cost too much?
						memory: memory.expect("memory data to not be filtered out"),
						stack: stack.expect("stack data to not be filtered out"),
					});
				}
			}
			RuntimeEvent::StepResult { result, return_value: _ } => {
				// StepResult is expected to be emited after a step (in a context).
				// Only case StepResult will occur without a Step before is in a transfer
				// transaction to a non-contract address. However it will not contain any
				// steps and return an empty trace, so we can ignore this edge case.
				'outer: loop {
					if let Some(context) = self.context_stack.last_mut() {
						let code_address = context.code_address.unwrap_or(context.address);

						if let Some(current_step) = context.current_step.take() {
							let Step {
								opcode,
								gas_cost,
								pc,
								memory,
								stack,
							} = current_step;

							self.index = self.index + 1;
							let op = to_opcode(&opcode);

							let op_string = std::str::from_utf8(&opcode).unwrap();
							context.current_opcode = Some(op_string.to_string());

							if self.call_stack[0].base.start_index == -1 && *self.entry_pc.get(&pc).unwrap_or(&false) {
								self.call_stack[0].base.pc = pc;
								self.call_stack[0].base.start_index = self.index - 1;
								self.previous_jump = None;
								break 'outer;
							}
							let mut base_trace = SentioBaseTrace {
								tracer_config: None,
								pc,
								start_index: self.index - 1,
								end_index: self.index,
								op,
								gas: context.gas,
								gas_used: gas_cost,
								error: None,
								revert_reason: None,
							};

							base_trace.error = match &result {
								Err(Capture::Exit(reason)) => {
									let res = match &reason {
										ExitReason::Error(error) => Some(error_message(error)),
										ExitReason::Revert(_) => Some(b"execution reverted".to_vec()),
										ExitReason::Fatal(_) => Some(vec![]),
										_ => None
									};
									res
								}
								_ => None,
							};

							match op {
								Opcode::CREATE | Opcode::CREATE2 | Opcode::CALL | Opcode::CALLCODE | Opcode::DELEGATECALL | Opcode::STATICCALL | Opcode::SUICIDE => {
									let call_trace: SentioCallTrace = SentioCallTrace::new(base_trace);
									self.call_stack.push(call_trace)
								}
								Opcode::LOG0 | Opcode::LOG1 | Opcode::LOG2 | Opcode::LOG3 | Opcode::LOG4 => {
									let topic_count = (op.as_u8() - Opcode::LOG0.as_u8()) as u64;
									let log_offset = stack_back(&stack, 0);
									let log_size = stack_back(&stack, 1);
									let data = copy_memory(&memory, log_offset.to_low_u64_be() as usize, log_size.to_low_u64_be() as usize);
									let mut topics: Vec<H256> = Vec::new();
									for i in 0..topic_count {
										topics.push(*stack_back(&stack, 2 + i))
									}

									let log_trace = SentioEventTrace {
										base: base_trace,
										log: sentio::Log {
											address: context.address,
											code_address,
											topics,
											data,
										},
									};
									let last = self.call_stack.last_mut().expect("call stack should not be empty");
									last.traces.push(SentioTrace::EventTrace(log_trace))
								}
								Opcode::JUMP if self.tracer_config.with_internal_calls => {
									let mut jump = SentioCallTrace::new(base_trace);
									jump.from = code_address;

									if self.previous_jump.is_some() {
										log::error!("Unexpected previous jump {}", self.index)
									}
									self.previous_jump = Some(jump);
								}
								Opcode::JUMPDEST if self.tracer_config.with_internal_calls => {
									// vm.JumpDest and match with a previous jump (otherwise it's a jumpi)
									if let Some(mut previous_jump) = self.previous_jump.take() {
										let stack_size = self.call_stack.len();

										// Part 1: try process the trace as function call exit
										for i in (0..stack_size).rev() {
											// process internal call within the same contract
											// no function info means another external call
											let function_info = &self.call_stack[i].function;
											let function_info = match function_info {
												None => break,
												Some(f) => f
											};

											if function_info.address != code_address {
												break;
											}

											// find a match
											if self.call_stack[i].exit_pc == pc {
												// find a match, pop the stack, copy memory if needed
												if stack_size - i > 1 {
													log::info!("tail call optimization size {}", stack_size -1)
												}

												for j in (i..stack_size).rev() {
													let mut element = self.call_stack.pop().expect("stack should have element");

													let function_j = element.function.as_ref().expect("function should existed");

													element.base.end_index = self.index - 1;
													element.base.gas_used = element.base.gas - context.gas;
													if function_j.output_size as usize > stack.data.len() {
														log::error!("stack size not enough ({} vs {}) for function {} {}. pc: {}",
														stack.data.len(), function_j.output_size, function_j.address, function_j.name, pc)
													} else {
														element.output_stack = copy_stack(&stack, function_j.output_size as usize);
													}
													if function_j.output_memory {
														element.output_memory = Some(format_memory(&memory.data));
													}

													self.call_stack[j - 1].traces.push(SentioTrace::CallTrace(element));
												}
												// self.previous_jump = None;
												break 'outer;
											}
										}

										// Part 2: try process the trace as function call entry
										// filter those jump are not call site
										if let Some(function_info) = self.get_function_info(code_address, pc) {
											if !self.is_call(previous_jump.from, previous_jump.base.pc) {
												break 'outer;
											}

											if function_info.input_size as usize > stack.data.len() {
												log::error!("Unexpected stack size for function: {:?}\nPrevious Jump: {:?}", function_info, previous_jump);
												break 'outer;
											}

											previous_jump.exit_pc = stack_back(&stack, function_info.input_size).to_low_u64_be();
											previous_jump.function = Some(function_info.clone());
											previous_jump.function_pc = pc;
											previous_jump.input_stack = copy_stack(&stack, function_info.input_size as usize);
											if self.tracer_config.debug {
												previous_jump.name = Some(function_info.name.clone());
											}
											if function_info.input_memory {
												previous_jump.input_memory = Some(format_memory(&memory.data))
											}
											self.call_stack.push(previous_jump)
										}
									}
								}
								Opcode::REVERT if self.tracer_config.with_internal_calls => {
									let log_offset = stack_back(&stack, 0).to_low_u64_be() as usize;
									let log_size = stack_back(&stack, 1).to_low_u64_be() as usize;
									let output = &memory.data[log_offset..(log_offset + log_size)];

									base_trace.error = Some(b"execution reverted".to_vec());
									base_trace.revert_reason = unpack_revert(&output)
								}
								_ if self.tracer_config.with_internal_calls => {
									if base_trace.error.is_some() {
										let last = self.call_stack.last_mut().expect("call stack should not be empty");
										last.traces.push(SentioTrace::OtherTrace(base_trace))
									}
								}
								_ => {}
							}
						}
					}
					break;
				} // outer loop

				// TODO update storage if needed
				// // We match on the capture to handle traps/exits.
				// match result {
				// 	Err(Capture::Exit(reason)) => { // OP could be return & STOP & CALL (immediate revert) & any (oos)
				// 		if let Some(context) = self.context_stack.pop() {
				// 			let stack_size = self.call_stack.len();
				// 			for i in (0..stack_size).rev() {
				// 				if self.call_stack[i].function.is_some() {
				// 					continue;
				// 				}
				//
				// 				if stack_size - i > 1 {
				// 					log::info!("tail call optimization [external] size {}", stack_size - i);
				// 				}
				//
				// 				let mut call = self.call_stack.get_mut(i).expect("call should exist");
				// 				call.process_error(&return_value, &reason);
				// 				// let gas = call.base.gas - context.gas_used;
				// 				self.pop_stack(i, &return_value, context.gas);
				// 				return;
				// 			}
				// 		}
				// 	}
				// 	_ => (),
				// } // match result
			}
			_ => {}
		}
	}

	fn create_root_trace(&mut self, from: H160, to: H160, op: Opcode, value: U256, data: Vec<u8>) {
		if (op == Opcode::CALL || op == Opcode::CALLCODE) && data.len() >= 4 { // also not precompile
			if let Some(m) = self.function_map.get(&to) {
				let sig_hash = format!("0x{}", hex::encode(&data[0..4]));

				for (pc, func) in m {
					if func.signature_hash == sig_hash {
						self.entry_pc.insert(*pc, true);
					}
				}
				log::info!("entry pc match {} ({} times)", sig_hash, self.entry_pc.len());
			}
		}

		let base_trace = SentioBaseTrace {
			tracer_config: None,
			op,
			start_index: -1,
			gas: 0,
			pc: 0,
			end_index: 0,
			gas_used: 0,
			error: None,
			revert_reason: None,
		};
		let call = SentioCallTrace {
			base: base_trace,
			from,
			to: Some(to),
			input: data,
			value,

			name: None,
			output: vec![],
			traces: vec![],
			input_stack: vec![],
			input_memory: None,
			output_stack: vec![],
			output_memory: None,
			function_pc: 0,
			exit_pc: 0,
			function: None,
		};
		self.call_stack.push(call);

		// no need to push context stack since it's record in gas step
		self.context_stack.push(Context {
			address: to,
			code_address: None,
			current_step: None,
			current_opcode: None,
			gas: 0,
			start_gas: 0,
		});

	}

	fn patch_call_trace(&mut self, code_address: H160, transfer: Option<evm_tracing_events::evm::Transfer>,
											input: Vec<u8>,
											context: evm_tracing_events::Context) {
		let value = transfer.map(|t| t.value).unwrap_or_default();
		if self.call_stack.is_empty() {
			// Legacy mode
			self.create_root_trace(context.caller, context.address, Opcode::CALL, value, input);
		} else if self.call_stack.len() > 1 { // the first Call will happen after TransactCall and it's
			let mut call = self.call_stack.last_mut().expect("not none");
			if call.function != None {
				panic!("find internal call when setting external call trace")
			}
			call.from = context.caller;
			call.to = Some(context.address);
			call.input = input;
			call.value = value;

			let call_context = self.context_stack.last_mut().expect("context stack should not be empty");
			call_context.address = context.address;
			call_context.code_address = Some(code_address);
		}
	}

	pub fn evm_event(&mut self, event: EvmEvent) {
		match event {
			EvmEvent::TransactCall { caller, address, value, data, .. } => {
				self.version = TracingVersion::EarlyTransact;
				self.create_root_trace(caller, address, Opcode::CALL, value, data);
			}
			EvmEvent::TransactCreate { caller, value, init_code, address, .. }
			| EvmEvent::TransactCreate2 { caller, value, init_code, address, .. } => {
				self.version = TracingVersion::EarlyTransact;
				self.create_root_trace(caller, address, Opcode::CREATE, value, init_code);
			}
			EvmEvent::Call { code_address, transfer, input, context, .. } => {
				self.patch_call_trace(code_address, transfer, input, context);
			}
			EvmEvent::PrecompileSubcall { code_address, transfer, input, context, .. } => {
				self.patch_call_trace(code_address, transfer, input, context);
				log::warn!("precompiled call found")
			}
			EvmEvent::Create { caller, address, value, init_code, .. } => {
				if self.call_stack.is_empty() {
					// Legacy mode
					self.create_root_trace(caller, address, Opcode::CREATE, value, init_code);
				} else if self.call_stack.len() > 1 {
					let mut call = self.call_stack.last_mut().expect("not none");

					if call.function != None {
						panic!("find internal call when setting external call trace")
					}
					call.from = caller;
					call.to = Some(address);
					call.input = init_code;
					call.value = value;
				}
			}
			EvmEvent::Suicide { .. } => {
				// no extra information to add
			}
			EvmEvent::Exit { reason, return_value } => {
				// We match on the capture to handle traps/exits.
				// match result {
				// 	Err(Capture::Exit(reason)) => { // OP could be return & STOP & CALL (immediate revert) & any (oos)
				if let Some(context) = self.context_stack.pop() {
					let used_gas = context.used_gas();
					if let Some(previous_context) = self.context_stack.last_mut() {
						// For early exit like OOS there no chance to update previous context
						previous_context.gas -= used_gas;
					}

					let stack_size = self.call_stack.len();
					for i in (0..stack_size).rev() {
						if self.call_stack[i].function.is_some() {
							continue;
						}

						if stack_size - i > 1 {
							log::info!("tail call optimization [external] size {}", stack_size - i);
						}

						let call = self.call_stack.get_mut(i).expect("call should exist");
						call.process_error(&return_value, &reason);
						// let gas = call.base.gas - context.gas_used;
						self.pop_stack(i, &return_value, context.start_gas - used_gas);
						return;
					}
				}
			}
			// 	_ => (),
			// } // match result

			// Only try to deal with precompile call here
			// If it's precompile, since no exit SteoResult::event will be emitted, direct pop the stack
			// if let Some(context) = self.context_stack.last() {
			// 	if self.precompile_address.contains(&context.code_address.unwrap_or(H160::default())) {
			// 		let mut call = self.call_stack.pop().expect("not none");
			// 		call.process_error(&return_value, &reason);
			// 		call.output = return_value;
			// 		self.call_stack.last_mut().expect("last not none").traces.push(SentioTrace::CallTrace(call));
			// 	}
			// }
			// }
		}
	}

	fn pop_stack(&mut self, to: usize, output: &Vec<u8>, gas_left: u64) {
		let stack_size = self.call_stack.len();
		for _ in to..stack_size {
			let mut call = self.call_stack.pop().expect("not null");
			call.output = output.clone();
			call.base.end_index = self.index;
			call.base.gas_used = call.base.gas - gas_left;

			match self.call_stack.last_mut() {
				Some(peek) => {
					peek.traces.push(SentioTrace::CallTrace(call));
				}
				None => {
					// keep the root to process in finish transaction
					self.call_stack.push(call)
				}
			}
		}
	}

	fn get_function_info(&self, address: H160, pc: u64) -> Option<&FunctionInfo> {
		match self.function_map.get(&address) {
			Some(m) => {
				m.get(&pc)
			}
			None => None
		}
	}

	fn is_call(&self, address: H160, pc: u64) -> bool {
		match self.call_map.get(&address) {
			Some(m) => {
				*m.get(&pc).unwrap_or(&false)
			}
			None => false
		}
	}
}

fn error_message(error: &ExitError) -> Vec<u8> {
	match error {
		ExitError::StackUnderflow => "stack underflow",
		ExitError::StackOverflow => "stack overflow",
		ExitError::InvalidJump => "invalid jump",
		ExitError::InvalidRange => "invalid range",
		ExitError::DesignatedInvalid => "designated invalid",
		ExitError::CallTooDeep => "call too deep",
		ExitError::CreateCollision => "create collision",
		ExitError::CreateContractLimit => "create contract limit",
		ExitError::OutOfOffset => "out of offset",
		ExitError::OutOfGas => "out of gas",
		ExitError::OutOfFund => "out of funds",
		ExitError::Other(err) => err,
		_ => "unexpected error",
	}
		.as_bytes()
		.to_vec()
}

impl ListenerT for Listener {
	fn event(&mut self, event: Event) {
		match event {
			Event::Gasometer(gasometer_event) => self.gasometer_event(gasometer_event),
			Event::Runtime(runtime_event) => self.runtime_event(runtime_event),
			Event::Evm(evm_event) => self.evm_event(evm_event),
			Event::CallListNew() => {
				if !self.call_list_first_transaction {
					self.finish_transaction();
					// self.skip_next_context = false;
					// self.entries.push(BTreeMap::new());
				} else {
					self.call_list_first_transaction = false;
				}
			}
		};
	}

	fn step_event_filter(&self) -> StepEventFilter {
		StepEventFilter {
			enable_memory: true,
			enable_stack: true,
		}
	}
}

impl SentioCallTrace {
	fn process_error(&mut self, output: &Vec<u8>, reason: &ExitReason) {
		let (error, revert_reason) = match reason {
			ExitReason::Revert(_) => {
				(Some(b"execution reverted".to_vec()), unpack_revert(output))
			}
			ExitReason::Fatal(_) => {
				log::error!("unexpected fatal");
				(Some(vec![]), None)
			}
			ExitReason::Error(error) => {
				(Some(error_message(error)), None)
			}
			ExitReason::Succeed(_) => {
				(None, None)
			}
		};
		if error.is_none() {
			return;
		}
		if self.base.op == Opcode::CREATE || self.base.op == Opcode::CREATE2 {
			self.to = None;
		}
		self.base.error = error;
		self.base.revert_reason = revert_reason;
	}
}

fn stack_back(stack: &Stack, n: u64) -> &H256 {
	return stack.data.get(stack.data.len() - (n as usize) - 1).expect("stack shouldn't be empty");
}

fn copy_stack(stack: &Stack, copy_size: usize) -> Vec<U256> {
	let stack_size = stack.data.len();
	let mut res: Vec<U256> =  vec![U256::zero(); stack_size - copy_size];

	for i in (stack_size - copy_size)..stack_size {
		res.push(U256::from(stack.data[i].as_bytes()));
	}
	return res;
}

fn copy_memory(memory: &Memory, offset: usize, size: usize) -> Vec<u8> {
	if memory.data.len() > offset {
		let mut end = offset + size;
		if memory.data.len() > end {
			end = memory.data.len()
		}
		return Vec::from_iter(memory.data[offset..end].iter().cloned());
	}
	return Vec::default();
}

// copied from type but change memory to reference
pub fn format_memory(memory: &Vec<u8>) -> Vec<H256> {
	let size = 32;
	memory
		.chunks(size)
		.map(|c| {
			let mut msg = [0u8; 32];
			let chunk = c.len();
			if chunk < size {
				let left = size - chunk;
				let remainder = vec![0; left];
				msg[0..left].copy_from_slice(&remainder[..]);
				msg[left..size].copy_from_slice(c);
			} else {
				msg[0..size].copy_from_slice(c)
			}
			H256::from_slice(&msg[..])
		})
		.collect()
}

// UnpackRevert resolves the abi-encoded revert reason. According to the solidity
// spec https://solidity.readthedocs.io/en/latest/control-structures.html#revert,
// the provided revert reason is abi-encoded as if it were a call to a function
// `Error(string)`. So it's a special tool for it.
pub fn unpack_revert(output: &[u8]) -> Option<Vec<u8>> {
	if output.len() < 4 {
		return None;
	}
	let revert_selector = &Keccak256::digest("Error(string)")[0..4];
	if output[0..4] != *revert_selector {
		return None;
	}
	let data = &output[4..];
	if let Some((start, length)) = length_prefix_points_to(0, data) {
		let bytes = data[start..start + length].to_vec();
		// let reason = std::str::from_utf8(&bytes).unwrap();
		return Some(bytes);
	}
	return None;
}

fn length_prefix_points_to(index: usize, output: &[u8]) -> Option<(usize, usize)> {
	let mut big_offset_end = U256::from(&output[index..index + 32]);
	big_offset_end = big_offset_end + U256::from(32);
	let output_length = U256::from(output.len());

	if big_offset_end > output_length {
		log::error!("abi: cannot marshal in to go slice: offset {} would go over slice boundary (len={})", big_offset_end, output_length);
		return None;
	}

	if big_offset_end.bits() > 63 {
		log::error!("abi offset larger than int64: {}", big_offset_end);
		return None;
	}

	let offset_end = big_offset_end.as_u64() as usize;
	let length_big = U256::from(&output[offset_end - 32..offset_end]);

	let total_size = big_offset_end + length_big;
	if total_size.bits() > 63 {
		log::error!("abi: length larger than int64: {}", total_size);
		return None;
	}

	if total_size > output_length {
		log::error!("abi: cannot marshal in to go type: length insufficient {} require {}", output_length, total_size);
		return None;
	}

	let start = big_offset_end.as_u64() as usize;
	let length = length_big.as_u64() as usize;
	return Some((start, length));
}

#[test]
fn test_unpack_revert() {
	let output_hex = "08c379a00000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000002f416e7973776170563345524332303a207472616e7366657220616d6f756e7420657863656564732062616c616e63650000000000000000000000000000000000";
	assert_eq!(unpack_revert(&hex::decode(output_hex).unwrap()), Some(b"AnyswapV3ERC20: transfer amount exceeds balance".to_vec()));
	assert_eq!(unpack_revert(&hex::decode("08c379a1").unwrap()), None);
	assert_eq!(unpack_revert(&hex::decode("").unwrap()), None);
}

pub fn to_opcode(opcode: &Vec<u8>) -> Opcode {
	let op_string = std::str::from_utf8(&opcode).unwrap();
	let out = match op_string.as_ref() {
		"Stop" => Opcode(0),
		"Add" => Opcode(1),
		"Mul" => Opcode(2),
		"Sub" => Opcode(3),
		"Div" => Opcode(4),
		"SDiv" => Opcode(5),
		"Mod" => Opcode(6),
		"SMod" => Opcode(7),
		"AddMod" => Opcode(8),
		"MulMod" => Opcode(9),
		"Exp" => Opcode(10),
		"SignExtend" => Opcode(11),
		"Lt" => Opcode(16),
		"Gt" => Opcode(17),
		"Slt" => Opcode(18),
		"Sgt" => Opcode(19),
		"Eq" => Opcode(20),
		"IsZero" => Opcode(21),
		"And" => Opcode(22),
		"Or" => Opcode(23),
		"Xor" => Opcode(24),
		"Not" => Opcode(25),
		"Byte" => Opcode(26),
		"Shl" => Opcode(27),
		"Shr" => Opcode(28),
		"Sar" => Opcode(29),
		"Keccak256" => Opcode(32),
		"Address" => Opcode(48),
		"Balance" => Opcode(49),
		"Origin" => Opcode(50),
		"Caller" => Opcode(51),
		"CallValue" => Opcode(52),
		"CallDataLoad" => Opcode(53),
		"CallDataSize" => Opcode(54),
		"CallDataCopy" => Opcode(55),
		"CodeSize" => Opcode(56),
		"CodeCopy" => Opcode(57),
		"GasPrice" => Opcode(58),
		"ExtCodeSize" => Opcode(59),
		"ExtCodeCopy" => Opcode(60),
		"ReturnDataSize" => Opcode(61),
		"ReturnDataCopy" => Opcode(62),
		"ExtCodeHash" => Opcode(63),
		"BlockHash" => Opcode(64),
		"Coinbase" => Opcode(65),
		"Timestamp" => Opcode(66),
		"Number" => Opcode(67),
		"Difficulty" => Opcode(68),
		"GasLimit" => Opcode(69),
		"ChainId" => Opcode(70),
		"Pop" => Opcode(80),
		"MLoad" => Opcode(81),
		"MStore" => Opcode(82),
		"MStore8" => Opcode(83),
		"SLoad" => Opcode(84),
		"SStore" => Opcode(85),
		"Jump" => Opcode(86),
		"JumpI" => Opcode(87),
		"GetPc" => Opcode(88),
		"MSize" => Opcode(89),
		"Gas" => Opcode(90),
		"JumpDest" => Opcode(91),
		"Push1" => Opcode(96),
		"Push2" => Opcode(97),
		"Push3" => Opcode(98),
		"Push4" => Opcode(99),
		"Push5" => Opcode(100),
		"Push6" => Opcode(101),
		"Push7" => Opcode(102),
		"Push8" => Opcode(103),
		"Push9" => Opcode(104),
		"Push10" => Opcode(105),
		"Push11" => Opcode(106),
		"Push12" => Opcode(107),
		"Push13" => Opcode(108),
		"Push14" => Opcode(109),
		"Push15" => Opcode(110),
		"Push16" => Opcode(111),
		"Push17" => Opcode(112),
		"Push18" => Opcode(113),
		"Push19" => Opcode(114),
		"Push20" => Opcode(115),
		"Push21" => Opcode(116),
		"Push22" => Opcode(117),
		"Push23" => Opcode(118),
		"Push24" => Opcode(119),
		"Push25" => Opcode(120),
		"Push26" => Opcode(121),
		"Push27" => Opcode(122),
		"Push28" => Opcode(123),
		"Push29" => Opcode(124),
		"Push30" => Opcode(125),
		"Push31" => Opcode(126),
		"Push32" => Opcode(127),
		"Dup1" => Opcode(128),
		"Dup2" => Opcode(129),
		"Dup3" => Opcode(130),
		"Dup4" => Opcode(131),
		"Dup5" => Opcode(132),
		"Dup6" => Opcode(133),
		"Dup7" => Opcode(134),
		"Dup8" => Opcode(135),
		"Dup9" => Opcode(136),
		"Dup10" => Opcode(137),
		"Dup11" => Opcode(138),
		"Dup12" => Opcode(139),
		"Dup13" => Opcode(140),
		"Dup14" => Opcode(141),
		"Dup15" => Opcode(142),
		"Dup16" => Opcode(143),
		"Swap1" => Opcode(144),
		"Swap2" => Opcode(145),
		"Swap3" => Opcode(146),
		"Swap4" => Opcode(147),
		"Swap5" => Opcode(148),
		"Swap6" => Opcode(149),
		"Swap7" => Opcode(150),
		"Swap8" => Opcode(151),
		"Swap9" => Opcode(152),
		"Swap10" => Opcode(153),
		"Swap11" => Opcode(154),
		"Swap12" => Opcode(155),
		"Swap13" => Opcode(156),
		"Swap14" => Opcode(157),
		"Swap15" => Opcode(158),
		"Swap16" => Opcode(159),
		"Log0" => Opcode(160),
		"Log1" => Opcode(161),
		"Log2" => Opcode(162),
		"Log3" => Opcode(163),
		"Log4" => Opcode(164),
		"JumpTo" => Opcode(176),
		"JumpIf" => Opcode(177),
		"JumpSub" => Opcode(178),
		"JumpSubv" => Opcode(180),
		"BeginSub" => Opcode(181),
		"BeginData" => Opcode(182),
		"ReturnSub" => Opcode(184),
		"PutLocal" => Opcode(185),
		"GetLocal" => Opcode(186),
		"SLoadBytes" => Opcode(225),
		"SStoreBytes" => Opcode(226),
		"SSize" => Opcode(227),
		"Create" => Opcode(240),
		"Call" => Opcode(241),
		"CallCode" => Opcode(242),
		"Return" => Opcode(243),
		"DelegateCall" => Opcode(244),
		"Create2" => Opcode(245),
		"StaticCall" => Opcode(250),
		"TxExecGas" => Opcode(252),
		"Revert" => Opcode(253),
		"Invalid" => Opcode(254),
		"SelfDestruct" => Opcode(255),
		_ => Opcode(0)
	};
	return out;
}
