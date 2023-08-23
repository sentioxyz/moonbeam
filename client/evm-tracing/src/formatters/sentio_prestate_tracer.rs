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

use std::marker::PhantomData;
use fp_rpc::EthereumRuntimeRPCApi;
use sp_api::{BlockT, ProvideRuntimeApi};
use sp_block_builder::BlockBuilder;
use crate::types::single::TransactionTrace;

use crate::listeners::sentio_prestate::Listener;

pub struct Formatter<B, C>
	where
		B: BlockT,
		C:ProvideRuntimeApi<B>,
		C::Api: EthereumRuntimeRPCApi<B>,
		C::Api: BlockBuilder<B> {
	_b: PhantomData<B>,
	_c: PhantomData<C>
}

impl<B, C> super::ResponseFormatter for Formatter<B, C>
	where
		B: BlockT,
		C:ProvideRuntimeApi<B> + 'static,
		C::Api: EthereumRuntimeRPCApi<B>,
		C::Api: BlockBuilder<B>
{
	type Listener = Listener<B, C>;
	type Response = Vec<TransactionTrace>;

	fn format(listener: Listener<B, C>) -> Option<Vec<TransactionTrace>> {
		if listener.results.is_empty() {
			None
		} else {
			Some(listener.results.into_iter().map(|trace| TransactionTrace::SentioPrestateTrace(trace)).collect())
		}
	}
}
