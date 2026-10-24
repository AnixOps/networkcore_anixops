//! Server name from the first TLS record of a flow.

/// The SNI host name of a TLS ClientHello, lowercased, when `first` starts
/// with one. A ClientHello cut short by the first read yields `None`.
pub fn client_hello_server_name(first: &[u8]) -> Option<String> {
    // TLS record: content type 22 (handshake), version, length.
    if first.len() < 5 || first[0] != 0x16 || first[1] != 0x03 {
        return None;
    }
    let record_len = usize::from(u16::from_be_bytes([first[3], first[4]]));
    let record = first.get(5..5 + record_len.min(first.len() - 5))?;
    let mut reader = Reader(record);
    // Handshake header: type 1 (ClientHello) and a 24-bit length.
    if reader.u8()? != 0x01 {
        return None;
    }
    reader.skip(3)?;
    reader.skip(2 + 32)?; // legacy_version, random
    let session_id = usize::from(reader.u8()?);
    reader.skip(session_id)?;
    let suites = usize::from(reader.u16()?);
    reader.skip(suites)?;
    let compression = usize::from(reader.u8()?);
    reader.skip(compression)?;
    let extensions_len = usize::from(reader.u16()?);
    let mut extensions = Reader(reader.take(extensions_len)?);
    while let Some(kind) = extensions.u16() {
        let len = usize::from(extensions.u16()?);
        let body = extensions.take(len)?;
        if kind != 0 {
            continue;
        }
        let mut list = Reader(body);
        let list_len = usize::from(list.u16()?);
        let mut names = Reader(list.take(list_len)?);
        while let Some(name_type) = names.u8() {
            let name_len = usize::from(names.u16()?);
            let name = names.take(name_len)?;
            if name_type == 0 {
                let name = std::str::from_utf8(name).ok()?;
                let valid = !name.is_empty()
                    && name.len() <= 253
                    && name
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_'));
                return valid.then(|| name.trim_end_matches('.').to_ascii_lowercase());
            }
        }
        return None;
    }
    None
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, len: usize) -> Option<&'a [u8]> {
        if self.0.len() < len {
            return None;
        }
        let (head, rest) = self.0.split_at(len);
        self.0 = rest;
        Some(head)
    }

    fn skip(&mut self, len: usize) -> Option<()> {
        self.take(len).map(|_| ())
    }

    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|bytes| bytes[0])
    }

    fn u16(&mut self) -> Option<u16> {
        self.take(2)
            .map(|bytes| u16::from_be_bytes([bytes[0], bytes[1]]))
    }
}

#[cfg(test)]
mod tests {
    use super::client_hello_server_name;

    fn client_hello(server_name: &str) -> Vec<u8> {
        let name = server_name.as_bytes();
        let mut sni = Vec::new();
        sni.extend_from_slice(&((name.len() + 3) as u16).to_be_bytes());
        sni.push(0);
        sni.extend_from_slice(&(name.len() as u16).to_be_bytes());
        sni.extend_from_slice(name);
        let mut extensions = Vec::new();
        // An unrelated extension first (supported_versions).
        extensions.extend_from_slice(&[0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04]);
        extensions.extend_from_slice(&[0x00, 0x00]);
        extensions.extend_from_slice(&(sni.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&sni);

        let mut hello = vec![0x03, 0x03];
        hello.extend_from_slice(&[0x11; 32]);
        hello.push(0);
        hello.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]);
        hello.extend_from_slice(&[0x01, 0x00]);
        hello.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        hello.extend_from_slice(&extensions);

        let mut handshake = vec![0x01];
        handshake.extend_from_slice(&(hello.len() as u32).to_be_bytes()[1..]);
        handshake.extend_from_slice(&hello);
        let mut record = vec![0x16, 0x03, 0x01];
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    #[test]
    fn reads_the_server_name() {
        assert_eq!(
            client_hello_server_name(&client_hello("API.Example.test.")).as_deref(),
            Some("api.example.test")
        );
    }

    #[test]
    fn rejects_other_records_and_truncation() {
        let hello = client_hello("api.example.test");
        assert_eq!(client_hello_server_name(b"GET / HTTP/1.1\r\n\r\n"), None);
        assert_eq!(client_hello_server_name(&hello[..hello.len() - 4]), None);
        assert_eq!(client_hello_server_name(&client_hello("bad name")), None);
        assert_eq!(client_hello_server_name(&[]), None);
    }
}
