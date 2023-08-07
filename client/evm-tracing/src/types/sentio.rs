use serde::Deserialize;

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

#[derive(Clone, Eq, PartialEq, Deserialize)]
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
