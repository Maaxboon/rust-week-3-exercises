use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use std::fmt;
use std::ops::Deref;

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct CompactSize {
    pub value: u64,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum BitcoinError {
    InsufficientBytes,
    InvalidFormat,
}

impl CompactSize {
    pub fn new(value: u64) -> Self {
        Self { value }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let v = self.value;
        if v <= 0xFC {
            vec![v as u8]
        } else if v <= 0xFFFF {
            let mut bytes = vec![0xFD];
            bytes.extend_from_slice(&(v as u16).to_le_bytes());
            bytes
        } else if v <= 0xFFFF_FFFF {
            let mut bytes = vec![0xFE];
            bytes.extend_from_slice(&(v as u32).to_le_bytes());
            bytes
        } else {
            let mut bytes = vec![0xFF];
            bytes.extend_from_slice(&v.to_le_bytes());
            bytes
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<(Self, usize), BitcoinError> {
        if bytes.is_empty() {
            return Err(BitcoinError::InsufficientBytes);
        }

        match bytes[0] {
            n @ 0x00..=0xFC => Ok((Self::new(n as u64), 1)),
            0xFD => {
                if bytes.len() < 3 {
                    return Err(BitcoinError::InsufficientBytes);
                }
                let val = u16::from_le_bytes([bytes[1], bytes[2]]) as u64;
                Ok((Self::new(val), 3))
            }
            0xFE => {
                if bytes.len() < 5 {
                    return Err(BitcoinError::InsufficientBytes);
                }
                let val = u32::from_le_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]) as u64;
                Ok((Self::new(val), 5))
            }
            0xFF => {
                if bytes.len() < 9 {
                    return Err(BitcoinError::InsufficientBytes);
                }
                let val = u64::from_le_bytes([
                    bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7], bytes[8],
                ]);
                Ok((Self::new(val), 9))
            } // _ => Err(BitcoinError::InvalidFormat),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Txid(pub [u8; 32]);

impl Serialize for Txid {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(self.0))
    }
}

impl<'de> Deserialize<'de> for Txid {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let hex_str = String::deserialize(deserializer)?;
        let bytes = hex::decode(&hex_str).map_err(de::Error::custom)?;
        if bytes.len() != 32 {
            return Err(de::Error::custom("Txid must be 32 bytes"));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Txid(arr))
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct OutPoint {
    pub txid: Txid,
    pub vout: u32,
}

impl OutPoint {
    pub fn new(txid: [u8; 32], vout: u32) -> Self {
        Self {
            txid: Txid(txid),
            vout,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.txid.0);
        bytes.extend_from_slice(&self.vout.to_le_bytes());
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<(Self, usize), BitcoinError> {
        if bytes.len() < 36 {
            return Err(BitcoinError::InsufficientBytes);
        }
        let mut txid = [0u8; 32];
        txid.copy_from_slice(&bytes[0..32]);
        let vout = u32::from_le_bytes(bytes[32..36].try_into().unwrap());
        Ok((OutPoint::new(txid, vout), 36))
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct Script {
    pub bytes: Vec<u8>,
}

impl Script {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut encoded = CompactSize::new(self.bytes.len() as u64).to_bytes();
        encoded.extend_from_slice(&self.bytes);
        encoded
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<(Self, usize), BitcoinError> {
        let (len_compact, len_size) = CompactSize::from_bytes(bytes)?;
        let len = len_compact.value as usize;

        if bytes.len() < len_size + len {
            return Err(BitcoinError::InsufficientBytes);
        }

        let script_bytes = bytes[len_size..len_size + len].to_vec();
        Ok((Script::new(script_bytes), len_size + len))
    }
}

impl Deref for Script {
    type Target = Vec<u8>;
    fn deref(&self) -> &Self::Target {
        &self.bytes
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct TransactionInput {
    pub previous_output: OutPoint,
    pub script_sig: Script,
    pub sequence: u32,
}

impl TransactionInput {
    pub fn new(previous_output: OutPoint, script_sig: Script, sequence: u32) -> Self {
        Self {
            previous_output,
            script_sig,
            sequence,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = self.previous_output.to_bytes();
        bytes.extend(self.script_sig.to_bytes());
        bytes.extend_from_slice(&self.sequence.to_le_bytes());
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<(Self, usize), BitcoinError> {
        let (prev_out, offset1) = OutPoint::from_bytes(bytes)?;
        let (script_sig, offset2) = Script::from_bytes(&bytes[offset1..])?;
        let offset_total = offset1 + offset2;
        if bytes.len() < offset_total + 4 {
            return Err(BitcoinError::InsufficientBytes);
        }
        let sequence =
            u32::from_le_bytes(bytes[offset_total..offset_total + 4].try_into().unwrap());
        Ok((
            TransactionInput::new(prev_out, script_sig, sequence),
            offset_total + 4,
        ))
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct BitcoinTransaction {
    pub version: u32,
    pub inputs: Vec<TransactionInput>,
    pub lock_time: u32,
}

impl BitcoinTransaction {
    pub fn new(version: u32, inputs: Vec<TransactionInput>, lock_time: u32) -> Self {
        Self {
            version,
            inputs,
            lock_time,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = self.version.to_le_bytes().to_vec();
        bytes.extend(CompactSize::new(self.inputs.len() as u64).to_bytes());
        for input in &self.inputs {
            bytes.extend(input.to_bytes());
        }
        bytes.extend_from_slice(&self.lock_time.to_le_bytes());
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<(Self, usize), BitcoinError> {
        if bytes.len() < 4 {
            return Err(BitcoinError::InsufficientBytes);
        }
        let version = u32::from_le_bytes(bytes[0..4].try_into().unwrap());

        let (input_count_cs, input_count_size) = CompactSize::from_bytes(&bytes[4..])?;
        let mut offset = 4 + input_count_size;
        let mut inputs = Vec::new();

        for _ in 0..input_count_cs.value {
            let (input, size) = TransactionInput::from_bytes(&bytes[offset..])?;
            inputs.push(input);
            offset += size;
        }

        if bytes.len() < offset + 4 {
            return Err(BitcoinError::InsufficientBytes);
        }
        let lock_time = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
        Ok((
            BitcoinTransaction::new(version, inputs, lock_time),
            offset + 4,
        ))
    }
}

impl fmt::Display for BitcoinTransaction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Version: {}", self.version)?;
        for input in &self.inputs {
            writeln!(
                f,
                "Previous Output Txid: {}",
                hex::encode(input.previous_output.txid.0)
            )?;
            writeln!(f, "Previous Output Vout: {}", input.previous_output.vout)?;
            writeln!(f, "ScriptSig: {}", hex::encode(&input.script_sig.bytes))?;
            writeln!(f, "Sequence: {}", input.sequence)?;
        }
        writeln!(f, "Lock Time: {}", self.lock_time)
    }
}
