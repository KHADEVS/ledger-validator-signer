//! A key held as shares on several devices: the partial signatures of enough of them give the
//! signature of the key. Nothing here holds a secret.

use bls12_381::hash_to_curve::{ExpandMsgXmd, HashToCurve};
use bls12_381::{pairing, G1Affine, G2Affine, G2Projective, Scalar};
use sha2::Sha256;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::time::Duration;

const DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

/// The signature of the key from partial ones, each with the number of its share.
pub fn combine(parts: &[(u8, [u8; 96])]) -> Option<[u8; 96]> {
    let mut total = G2Projective::identity();
    for (share, bytes) in parts {
        let point = Option::<G2Affine>::from(G2Affine::from_compressed(bytes))?;
        // Lagrange coefficient at zero: the product of j / (j - i) over the other shares.
        let mut coefficient = Scalar::one();
        for (other, _) in parts.iter().filter(|(other, _)| other != share) {
            let (i, j) = (Scalar::from(*share as u64), Scalar::from(*other as u64));
            coefficient *= j * Option::<Scalar>::from((j - i).invert())?;
        }
        total += G2Projective::from(point) * coefficient;
    }
    Some(G2Affine::from(total).to_compressed())
}

/// Whether `signature` is the key's signature of a signing root, as Ethereum checks it.
pub fn verify(public_key: &[u8; 48], root: &[u8; 32], signature: &[u8; 96]) -> bool {
    let key = Option::<G1Affine>::from(G1Affine::from_compressed(public_key));
    let signature = Option::<G2Affine>::from(G2Affine::from_compressed(signature));
    let (Some(key), Some(signature)) = (key, signature) else {
        return false;
    };
    let hashed = <G2Projective as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve(root, DST);
    pairing(&G1Affine::generator(), &signature) == pairing(&key, &G2Affine::from(hashed))
}

/// Every way to take `size` items out of `count`, as lists of positions.
pub fn subsets(count: usize, size: usize) -> Vec<Vec<usize>> {
    if size == 0 {
        return vec![Vec::new()];
    }
    let mut out = Vec::new();
    for first in 0..count {
        for mut rest in subsets(count - first - 1, size - 1) {
            for position in rest.iter_mut() {
                *position += first + 1;
            }
            rest.insert(0, first);
            out.push(rest);
        }
    }
    out
}

/// A plain HTTP request to a signer on the operator's own network: the status and the body.
pub fn http(method: &str, url: &str, body: &str, timeout: Duration) -> io::Result<(u16, String)> {
    let rest = url
        .strip_prefix("http://")
        .ok_or_else(|| io::Error::other("an http:// address is expected"))?;
    let (host, path) = match rest.find('/') {
        Some(at) => (&rest[..at], &rest[at..]),
        None => (rest, "/"),
    };
    let mut stream = TcpStream::connect(host)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    write!(
        stream,
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\nAccept: application/json\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )?;
    let mut answer = String::new();
    stream.read_to_string(&mut answer)?;
    let (head, body) = answer
        .split_once("\r\n\r\n")
        .ok_or_else(|| io::Error::other("not an HTTP answer"))?;
    let status = head
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .ok_or_else(|| io::Error::other("no HTTP status"))?;
    Ok((status, body.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bls12_381::G1Projective;

    fn partial(share: Scalar, root: &[u8; 32]) -> [u8; 96] {
        let hashed = <G2Projective as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve(root, DST);
        G2Affine::from(hashed * share).to_compressed()
    }

    #[test]
    fn two_shares_of_three_sign_for_the_key() {
        let (secret, slope) = (Scalar::from(123_456_789u64), Scalar::from(987_654_321u64));
        let key = G1Affine::from(G1Projective::generator() * secret).to_compressed();
        let root = [7u8; 32];
        let parts: Vec<(u8, [u8; 96])> = (1u8..=3)
            .map(|i| (i, partial(secret + slope * Scalar::from(i as u64), &root)))
            .collect();
        for pair in subsets(3, 2) {
            let chosen: Vec<_> = pair.iter().map(|p| parts[*p]).collect();
            let signature = combine(&chosen).expect("points of the curve");
            assert!(verify(&key, &root, &signature), "{pair:?}");
            assert!(
                !verify(&key, &[8u8; 32], &signature),
                "another root, {pair:?}"
            );
        }
        assert!(
            !verify(&key, &root, &parts[0].1),
            "one partial signature alone"
        );
        // A share under another number does not give the key's signature.
        let wrong = [(1u8, parts[0].1), (3u8, parts[1].1)];
        assert!(!verify(&key, &root, &combine(&wrong).expect("points")));
    }

    #[test]
    fn subsets_are_all_there_once() {
        assert_eq!(subsets(3, 2), vec![vec![0, 1], vec![0, 2], vec![1, 2]]);
        assert_eq!(subsets(4, 2).len(), 6);
        assert_eq!(subsets(2, 3).len(), 0);
        assert_eq!(subsets(3, 3), vec![vec![0, 1, 2]]);
    }
}
