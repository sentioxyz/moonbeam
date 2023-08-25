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

use ethereum_types::{H160, H256, U256};
use evm_tracing_events::{runtime::{Capture, ExitError, ExitReason, Memory, Opcode, Stack}, Event, EvmEvent, GasometerEvent, Listener as ListenerT, RuntimeEvent, StepEventFilter};
use std::{collections::HashMap, vec, vec::Vec, str::FromStr};

use crate::types::sentio;
use crate::listeners::sentio_util::{copy_memory, copy_stack, format_memory, stack_back, to_opcode, unpack_revert};
use crate::types::sentio::{SentioBaseTrace, FunctionInfo, SentioCallTrace, SentioEventTrace, SentioTrace};


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
	opcode: Opcode,
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
			GasometerEvent::RecordStipend { stipend, snapshot } => {
				if let Some(context) = self.context_stack.last_mut() {
					let gas = snapshot.gas();
					log::warn!("stipend {}, {} found, not battle tested", stipend, gas);
					// TODO check why this work
					context.gas += gas;
				}
			}
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
			RuntimeEvent::Step { context: _, opcode, position, stack, memory } => {
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
					if self.tracer_config.debug {
						let op_string = std::str::from_utf8(&opcode).unwrap();
						context.current_opcode = Some(op_string.to_string());
					}
					context.current_step = Some(Step {
						opcode: op,
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
								op: opcode,
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

							match opcode {
								Opcode::CREATE | Opcode::CREATE2 | Opcode::CALL | Opcode::CALLCODE | Opcode::DELEGATECALL | Opcode::STATICCALL | Opcode::SUICIDE => {
									let call_trace: SentioCallTrace = SentioCallTrace::new(base_trace);
									self.call_stack.push(call_trace)
								}
								Opcode::LOG0 | Opcode::LOG1 | Opcode::LOG2 | Opcode::LOG3 | Opcode::LOG4 => {
									let topic_count = (opcode.as_u8() - Opcode::LOG0.as_u8()) as u64;
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

