use crate::types::sentio;
use crate::types::serialization::*;

use ethereum_types::{H160, U256};
use ethereum::Log;
use parity_scale_codec::{Decode, Encode};
use serde::{Serialize, Deserialize};

#[derive(Clone, Eq, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SentioTracerConfig {
  #[serde(default)]
  pub functions: std::collections::HashMap<String, FunctionInfo>,

  #[serde(default)]
  pub calls: std::collections::HashMap<String, i64>,

  #[serde(default)]
  pub debug: bool,

  #[serde(default)]
  pub with_internal_calls: bool
}

#[derive(Clone, Eq, PartialEq, Debug, Deserialize)]
#[derive(Default)]
#[serde(rename_all = "camelCase")]
pub struct FunctionInfo {
  address:        String,
  name:           String,
  signature_hash: String,
  pc:             i64,
  input_size:     i32,
  input_memory:   bool,
  output_size:    i32,
  output_memory:  bool
}

#[derive(Clone, Eq, PartialEq, Default, Debug, Encode, Decode, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BaseSentioTrace {
  #[serde(rename = "type", serialize_with = "opcode_serialize")]
  pub op: Vec<u8>,
  pub pc: u64,
  pub start_index: i32,
  pub end_index: i32,
  pub gas: u64,
  pub gas_used: u64,
  #[serde(skip)]
  #[codec(skip)]
  pub gas_cost: u64,

  #[serde(serialize_with = "string_serialize", skip_serializing_if = "Vec::is_empty")]
  pub error: Vec<u8>,

  #[serde(serialize_with = "string_serialize", skip_serializing_if = "Vec::is_empty")]
  pub revert_reason: Vec<u8>,
}

#[derive(Clone, Eq, PartialEq, Debug, Encode, Decode, Serialize)]
#[serde(rename_all = "camelCase", untagged)]
pub enum SentioTrace {
  EventTrace(SentioEventTrace),
  CallTrace(SentioCallTrace),
  // InternalCallTrace(SentioInternalCallTrace)
}

#[derive(Clone, Eq, PartialEq, Debug, Encode, Decode, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SentioEventTrace {
  #[serde(flatten)]
  pub base: BaseSentioTrace,

  #[serde(flatten)]
  pub log: Log
}

#[derive(Clone, Eq, PartialEq, Default, Debug, Encode, Decode, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SentioCallTrace {
  #[serde(flatten)]
  pub base: BaseSentioTrace,
  pub traces: Vec<SentioTrace>,
  pub from: H160,
  #[serde(serialize_with = "bytes_0x_serialize")]
  pub output: Vec<u8>,

  // for external call
  pub to: H160,
  #[serde(serialize_with = "bytes_0x_serialize")]
  pub input: Vec<u8>,
  pub value: U256,

  // for internal trace
  pub input_stack: Vec<U256>,
  pub input_memory: Vec<String>,
  pub output_stack: Vec<U256>,
  pub output_memory: Vec<String>,
  pub function_pc: u64,
  #[serde(skip)]
  #[codec(skip)]
  pub exit_pc: u64,
  #[codec(skip)]
  #[serde(skip)]
  pub function: Option<*const sentio::FunctionInfo>
}
//
// #[derive(Clone, Eq, PartialEq, Debug, Encode, Decode, Serialize)]
// #[serde(rename_all = "camelCase")]
// pub struct SentioInternalCallTrace {
//   #[serde(skip_serializing_if = "Option::is_none")]
//   pub name: Option<String>,
//
//   #[serde(flatten)]
//   pub base: BaseSentioTrace,
//   pub traces: Vec<SentioTrace>,
//   pub from: H160,
//   #[serde(serialize_with = "bytes_0x_serialize")]
//   pub output: Vec<u8>,
//
//
// }
