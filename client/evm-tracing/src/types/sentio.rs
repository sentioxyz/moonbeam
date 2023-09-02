use std::collections::BTreeMap;
use crate::types::serialization::*;

use ethereum_types::{H160, H256, U256};
use parity_scale_codec::{Decode, Encode};
use serde::{Serialize, Deserialize, Serializer};
use serde::ser::Error;
use serde_json::Value;
use evm_tracing_events::runtime::{Opcode, opcodes_string};

#[derive(Clone, Eq, PartialEq, Debug, Default, Encode, Decode, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SentioTracerConfig {
	#[serde(default)]
	pub functions: BTreeMap<String, Vec<FunctionInfo>>,

	#[serde(default)]
	pub calls: BTreeMap<String, Vec<u64>>,

	#[serde(default)]
	pub debug: bool,

	#[serde(default)]
	pub with_internal_calls: bool,
}

#[derive(Clone, Eq, PartialEq, Debug, Default, Encode, Decode, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FunctionInfo {
	#[serde(default)]
	pub address: H160,
	pub name: String,
	pub signature_hash: String,
	pub pc: u64,
	pub input_size: u64,
	pub input_memory: bool,
	pub output_size: u64,
	pub output_memory: bool,
}

#[derive(Clone, Eq, PartialEq, Debug, Encode, Decode, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SentioBaseTrace {
	// Only in debug mode, TODO p3, make it vec<u8> and have it serialize to json
	#[serde(
		skip_serializing_if = "Option::is_none",
		serialize_with = "json_serialize"
	)]
	pub tracer_config: Option<Vec<u8>>,

	#[serde(rename = "type", serialize_with = "original_opcode_serialize")]
	pub op: Opcode,
	pub pc: u64,
	pub start_index: i32,
	pub end_index: i32,

	#[serde(serialize_with = "u64_serialize")]
	pub gas: u64,
	#[serde(serialize_with = "u64_serialize")]
	pub gas_used: u64,

	#[serde(
		skip_serializing_if = "Option::is_none",
		serialize_with = "option_string_serialize"
	)]
	pub error: Option<Vec<u8>>,

	#[serde(
		skip_serializing_if = "Option::is_none",
		serialize_with = "option_string_serialize"
	)]
	pub revert_reason: Option<Vec<u8>>,
}

#[derive(Clone, Eq, PartialEq, Debug, Encode, Decode, Serialize)]
#[serde(rename_all = "camelCase", untagged)]
pub enum SentioTrace {
	EventTrace(SentioEventTrace),
	CallTrace(SentioCallTrace),
	OtherTrace(SentioBaseTrace),
}

#[derive(Clone, Eq, PartialEq, Debug, Encode, Decode, Serialize)]
pub struct Log {
	pub address: H160,
	pub code_address: H160,
	pub topics: Vec<H256>,
	#[serde(serialize_with = "bytes_0x_serialize")]
	pub data: Vec<u8>,
}

#[derive(Clone, Eq, PartialEq, Debug, Encode, Decode, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SentioEventTrace {
	#[serde(flatten)]
	pub base: SentioBaseTrace,

	#[serde(flatten)]
	pub log: Log,
}

#[derive(Clone, Eq, PartialEq, Debug, Encode, Decode, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SentioCallTrace {
	#[serde(flatten)]
	pub base: SentioBaseTrace,
	pub traces: Vec<SentioTrace>,
	pub from: H160,
	#[serde(serialize_with = "bytes_0x_serialize")]
	pub output: Vec<u8>,

	// for external call
	#[serde(skip_serializing_if = "Option::is_none")]
	pub to: Option<H160>,
	#[serde(serialize_with = "bytes_0x_serialize")]
	pub input: Vec<u8>,
	pub value: U256,// TODO use some

	// for internal trace
	#[serde(skip_serializing_if = "Option::is_none")]
	pub name: Option<String>,
	// TODO remove trailing zero
	#[serde(skip_serializing_if = "Vec::is_empty")]
	pub input_stack: Vec<U256>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub input_memory: Option<Vec<H256>>,
	#[serde(skip_serializing_if = "Vec::is_empty")]
	pub output_stack: Vec<U256>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub output_memory: Option<Vec<H256>>,
	#[serde(skip_serializing_if = "is_zero")]
	pub function_pc: u64,
	#[serde(skip)]
	#[codec(skip)]
	pub exit_pc: u64,
	#[codec(skip)]
	#[serde(skip)]
	pub function: Option<FunctionInfo>,
}

impl SentioCallTrace {
	pub fn new(base_trace: SentioBaseTrace) -> Self {
		return SentioCallTrace {
			base: base_trace,
			traces: vec![],
			from: Default::default(),
			output: vec![],
			to: None,
			input: vec![],
			value: Default::default(),
			name: None,
			input_stack: vec![],
			input_memory: None,
			output_stack: vec![],
			output_memory: None,
			function_pc: 0,
			exit_pc: 0,
			function: None,
		};
	}
}

#[derive(Clone, Eq, PartialEq, Default, Debug, Encode, Decode, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SentioPrestateTracerConfig {
	#[serde(default)]
	pub diff_mode: bool,

	#[serde(default)]
	pub debug: bool,
}

#[derive(Clone, Eq, PartialEq, Debug, Encode, Decode, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Account {
	#[serde(skip_serializing_if = "Option::is_none")]
	pub balance: Option<U256>,

	#[serde(
		skip_serializing_if = "Vec::is_empty",
		serialize_with = "bytes_0x_serialize"
	)]
	pub code: Vec<u8>,

	#[serde(
	skip_serializing_if = "Option::is_none",
	serialize_with = "option_u256_serialize"
	)]
	pub nonce: Option<U256>,

	#[serde(skip_serializing_if = "BTreeMap::is_empty")]
	pub storage: BTreeMap<H256, H256>,

	#[serde(skip_serializing_if = "Option::is_none")]
	pub code_address: Option<H160>,

	#[serde(skip_serializing_if = "BTreeMap::is_empty")]
	pub mapping_keys: BTreeMap<String, H256>,
}

pub type State = BTreeMap<H160, Account>;

#[derive(Clone, Eq, PartialEq, Debug, Encode, Decode, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SentioPrestateTrace {
	#[serde(skip_serializing_if = "BTreeMap::is_empty")]
	pub pre: State,
	#[serde(skip_serializing_if = "BTreeMap::is_empty")]
	pub post: State,
}

pub fn option_u256_serialize<S>(data: &Option<U256>, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
{
	serializer.serialize_u64(data.unwrap_or_default().low_u64())
}


fn u64_serialize<S>(data: &u64, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
{
	serializer.serialize_str(&format!("0x{:x}", *data))
}

fn original_opcode_serialize<S>(data: &Opcode, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
{
	let bytes = opcodes_string(*data);
	return opcode_serialize(&bytes, serializer);
}

fn json_serialize<S>(data: &Option<Vec<u8>>, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
{
	if let Some(d) = data {
		let v: Value = serde_json::from_slice(d).unwrap();
		return v.serialize(serializer);
	}
	return Err(S::Error::custom("serialize error."));
}

fn is_zero(n: &u64) -> bool {
	return *n == 0;
}

#[test]
fn test_tracer_config_parse() {
	let config_string = "{\n  \"calls\": {\n    \"0x18dd7bca62deee6f633221de26096fdd0c734daa\": [\n      79\n    ],\n    \"0x3773e1e9deb273fcdf9f80bc88bb387b1e6ce34d\": [\n      2959\n    ]\n  },\n  \"debug\": true,\n  \"functions\": {\n    \"0x18dd7bca62deee6f633221de26096fdd0c734daa\": [\n      {\n        \"inputMemory\": false,\n        \"inputSize\": 1,\n        \"name\": \"_setImplementation\",\n        \"outputMemory\": false,\n        \"outputSize\": 0,\n        \"pc\": 1593,\n        \"signatureHash\": \"0x\"\n      }\n    ]\n  },\n  \"noInternalCalls\": false,\n  \"withInternalCalls\": true\n}";

	let v: SentioTracerConfig = serde_json::from_str(&config_string).unwrap();
	assert_eq!(v.debug, true);
	assert_eq!(v.calls.len(), 2);
	assert_eq!(v.functions.len(), 1);
}

#[test]
fn test_h256_to_u256() {
	let string = "0f02ba4d7f83e59eaa32eae9c3c4d99b68ce76decade21cdab7ecce8f4aef81a";
	let bytes = hex::decode(string).unwrap();
	let h256 = H256::from_slice(&bytes);
	let h256_bytes = h256.as_bytes();
	assert_eq!(h256_bytes, bytes);
	let u256 = U256::from(h256_bytes);
	let u256_string = serde_json::to_string(&u256).unwrap();
	let u256_sub = "0".to_string() + &u256_string[3..u256_string.len() - 1].to_string();
	assert_eq!(string, u256_sub);
}
