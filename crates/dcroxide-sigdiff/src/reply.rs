// SPDX-License-Identifier: ISC
//! A parsed oracle response line.

use std::collections::BTreeMap;

/// One response from `tools/oracle`: the fields the signature commands and
/// `build_info` answer with (its `response` struct), each absent when the
/// oracle omitted it.  Fields the signature commands never send (`txid`
/// and the like) are ignored.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Reply {
    /// The request's id, echoed; `None` on a reply to a request without one
    /// and on the error answering a line that did not decode.
    pub id: Option<u64>,
    /// The result: a verdict (`"true"`/`"false"`) or a value in hex.
    pub result: Option<String>,
    /// The error text, on failure.
    pub error: Option<String>,
    /// dcrd's error kind name (`ErrSig…`, `ErrPubKey…`), when the error has
    /// one.
    pub kind: Option<String>,
    /// The compressed key `pubkey_parse` adds, or the key `ed25519_sign`
    /// signed with.
    pub compressed: Option<String>,
    /// Whether a recovered key was compressed (`ecdsa_recover_compact`),
    /// sent as the string `"true"` or `"false"`.
    pub was_compressed: Option<bool>,
    /// The Go version (`build_info`).
    pub go_version: Option<String>,
    /// The signature modules' versions as the build resolved them
    /// (`build_info`); empty otherwise.
    pub modules: BTreeMap<String, String>,
    /// The response object as received, for the record of a disagreement.
    pub raw: String,
}

impl Reply {
    /// Parses one response line (its newline may be included).
    pub fn from_line(line: &str) -> Result<Reply, String> {
        let line = line.trim_end_matches(['\n', '\r']);
        let value: serde_json::Value =
            serde_json::from_str(line).map_err(|e| format!("not JSON ({e}): {line}"))?;
        Reply::read(&value, line.to_owned())
    }

    /// Reads a response from its JSON object, as testutil's `Oracle::call`
    /// returns it.
    pub fn from_json(value: &serde_json::Value) -> Result<Reply, String> {
        Reply::read(value, value.to_string())
    }

    /// Reads a response from its JSON object, `raw` being its text.
    fn read(value: &serde_json::Value, raw: String) -> Result<Reply, String> {
        let object = value
            .as_object()
            .ok_or_else(|| format!("not a JSON object: {value}"))?;
        let string = |name: &str| -> Result<Option<String>, String> {
            match object.get(name) {
                None => Ok(None),
                Some(serde_json::Value::String(s)) => Ok(Some(s.clone())),
                Some(other) => Err(format!("{name} is not a string: {other}")),
            }
        };
        let id = match object.get("id") {
            None => None,
            Some(v) => Some(
                v.as_u64()
                    .ok_or_else(|| format!("id is not an unsigned 64-bit integer: {v}"))?,
            ),
        };
        let was_compressed = match string("was_compressed")?.as_deref() {
            None => None,
            Some("true") => Some(true),
            Some("false") => Some(false),
            Some(other) => return Err(format!("was_compressed is {other:?}")),
        };
        let mut modules = BTreeMap::new();
        match object.get("modules") {
            None => {}
            Some(serde_json::Value::Object(map)) => {
                for (module, version) in map {
                    let version = version
                        .as_str()
                        .ok_or_else(|| format!("version of {module} is not a string"))?;
                    modules.insert(module.clone(), version.to_owned());
                }
            }
            Some(other) => return Err(format!("modules is not an object: {other}")),
        }
        Ok(Reply {
            id,
            result: string("result")?,
            error: string("error")?,
            kind: string("kind")?,
            compressed: string("compressed")?,
            was_compressed,
            go_version: string("go_version")?,
            modules,
            raw,
        })
    }

    /// The reply as a JSON value, for a record: the object as received.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::from_str(&self.raw)
            .unwrap_or_else(|_| serde_json::Value::String(self.raw.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every response shape the signature commands and `build_info` send.
    #[test]
    fn parses_each_response_shape() {
        let r = Reply::from_line("{\"id\":7,\"result\":\"true\"}\n").expect("verdict");
        assert_eq!((r.id, r.result.as_deref()), (Some(7), Some("true")));
        assert_eq!(r.raw, "{\"id\":7,\"result\":\"true\"}");

        let r = Reply::from_line(
            "{\"id\":18446744073709551615,\"error\":\"malformed signature: too short\",\"kind\":\"ErrSigTooShort\"}",
        )
        .expect("error with kind");
        assert_eq!(r.id, Some(u64::MAX));
        assert_eq!(r.error.as_deref(), Some("malformed signature: too short"));
        assert_eq!(r.kind.as_deref(), Some("ErrSigTooShort"));
        assert_eq!(r.result, None);

        let r = Reply::from_line("{\"id\":1,\"result\":\"04ab\",\"compressed\":\"02cd\"}")
            .expect("pubkey_parse");
        assert_eq!(
            (r.result.as_deref(), r.compressed.as_deref()),
            (Some("04ab"), Some("02cd"))
        );

        let r = Reply::from_line("{\"id\":2,\"result\":\"03ef\",\"was_compressed\":\"true\"}")
            .expect("recovery");
        assert_eq!(r.was_compressed, Some(true));
        let r =
            Reply::from_line("{\"result\":\"04ef\",\"was_compressed\":\"false\"}").expect("no id");
        assert_eq!((r.id, r.was_compressed), (None, Some(false)));

        let r = Reply::from_line(
            "{\"go_version\":\"go1.26.2\",\"modules\":{\"github.com/decred/dcrd/dcrec/edwards/v2\":\"v2.0.5\",\"github.com/decred/dcrd/dcrec/secp256k1/v4\":\"v4.4.2\"}}",
        )
        .expect("build_info");
        assert_eq!(r.go_version.as_deref(), Some("go1.26.2"));
        assert_eq!(r.modules.len(), 2);
        assert_eq!(
            r.modules["github.com/decred/dcrd/dcrec/secp256k1/v4"],
            "v4.4.2"
        );

        let r = Reply::from_line("{\"error\":\"bad request: unexpected end of JSON input\"}")
            .expect("an undecodable line's answer has no id");
        assert_eq!(r.id, None);

        let r = Reply::from_line("{\"id\":3,\"txid\":\"ab\",\"result\":\"false\"}")
            .expect("extra field");
        assert_eq!(r.result.as_deref(), Some("false"));
        assert_eq!(r.to_json()["txid"], "ab");

        let value: serde_json::Value =
            serde_json::from_str("{\"id\":4,\"result\":\"00\"}").expect("JSON");
        assert_eq!(Reply::from_json(&value).expect("from a value").id, Some(4));
    }

    /// Lines the oracle never sends are refused, with the reason.
    #[test]
    fn refuses_malformed_lines() {
        for line in [
            "",
            "not json",
            "[1,2]",
            "\"result\"",
            "{\"id\":-1}",
            "{\"id\":\"7\"}",
            "{\"id\":1.5}",
            "{\"result\":true}",
            "{\"was_compressed\":\"yes\"}",
            "{\"was_compressed\":true}",
            "{\"modules\":[]}",
            "{\"modules\":{\"m\":1}}",
        ] {
            assert!(Reply::from_line(line).is_err(), "{line:?}");
        }
    }
}
