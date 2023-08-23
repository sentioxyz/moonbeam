use ethereum_types::{H256, U256};
use sha3::{Digest, Keccak256};
use evm_tracing_events::runtime::{Memory, Opcode, Stack};

pub fn stack_back(stack: &Stack, n: u64) -> &H256 {
	return stack.data.get(stack.data.len() - (n as usize) - 1).expect("stack shouldn't be empty");
}

pub fn copy_stack(stack: &Stack, copy_size: usize) -> Vec<U256> {
	let stack_size = stack.data.len();
	let mut res: Vec<U256> = vec![U256::zero(); stack_size - copy_size];

	for i in (stack_size - copy_size)..stack_size {
		res.push(U256::from(stack.data[i].as_bytes()));
	}
	return res;
}

pub fn copy_memory(memory: &Memory, offset: usize, size: usize) -> Vec<u8> {
	if memory.data.len() > offset {
		let mut end = offset + size;
		if end > memory.data.len() {
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
