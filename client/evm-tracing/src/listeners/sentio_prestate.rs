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
use ethereum_types::H160;
use evm_tracing_events::{Event, EvmEvent, Listener as ListenerT, RuntimeEvent, StepEventFilter};
use crate::types::sentio::{State, SentioPrestateTrace, SentioPrestateTracerConfig};

pub struct Listener {
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

	call_list_first_transaction: bool
}

impl Listener {
	pub fn new(config: SentioPrestateTracerConfig) -> Self {
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
		}
	}
}

impl Listener {
	pub fn using<R, F: FnOnce() -> R>(&mut self, f: F) -> R {
		evm_tracing_events::using(self, f)
	}

	pub fn finish_transaction(&mut self) {}

	pub fn evm_event(&mut self, event: EvmEvent) {
		match event {
			EvmEvent::TransactCall { gas_limit, .. }
			| EvmEvent::TransactCreate { gas_limit, .. }
			| EvmEvent::TransactCreate2 { gas_limit, .. } => {
				self.gas_limit = gas_limit;
			}
			_ => {}
		}
	}

	pub fn runtime_event(&mut self, event: RuntimeEvent) {}
}

impl ListenerT for Listener {
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
