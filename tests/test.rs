#[cfg(test)]
mod tests {
    use pqx::*;
    use std::sync::mpsc::channel;
    use std::thread;
    use std::time::Duration;
    #[test]
    fn agreement() {
        let (sender1, receiver1) = channel();
        let (sender2, receiver2) = channel();
        let thread = thread::spawn(move || {
            let bob_s = Combinedkey::default();
            let bob_p = Combinedpub::new(&bob_s);
            sender1.send(bob_p.to_string()).unwrap();
            let cipher = receiver2.recv_timeout(Duration::new(20, 0)).unwrap();
            let cipher = Combinedcipher::from(cipher);
            Combinedshared::new(bob_s, cipher).unwrap()
        });
        let alice_s = Combinedkey::default();
        let pubkey = receiver1.recv_timeout(Duration::new(20, 0)).unwrap();
        let pubkey = Combinedpub::try_from(pubkey.as_str()).unwrap();
        let kyberelem = Combinedcipher::new(&alice_s, &pubkey).unwrap();
        sender2.send(kyberelem.getcipher()).unwrap();
        let shared = Combinedshared::getfromshared(kyberelem, pubkey, alice_s)
            .unwrap()
            .getshared(SHAREDSIZE::Med);
        let result = thread.join().unwrap().getshared(SHAREDSIZE::Med);
        assert!(
            shared == result,
            "Invalid shared, got {:#?} and {:#?}",
            shared,
            result
        );
        //println!("Valid shared, got {}",hex::encode(shared.get()))
    }
    #[test]
    #[cfg(feature = "keystore")]
    fn keys() {
        use std::fs;
        use tempfile::NamedTempFile;
        use pqx::key::*;
        let keys = Combinedkey::new();
        let privatefile = NamedTempFile::new().unwrap();
        let publicfile = NamedTempFile::new().unwrap();
        let privatetemp = privatefile.into_temp_path();
        let publictemp = publicfile.into_temp_path();
        printkeystofile(
            keys.getkyberkeypair(),
            &privatetemp,
            &publictemp,
        )
        .unwrap();
        let mut privatefile = fs::File::open(privatetemp).unwrap();
        let mut publicfile = fs::File::open(publictemp).unwrap();
        let testkey = extractkyberkeysfromfile(&mut publicfile, &mut privatefile).unwrap();
        assert!(testkey.checkkeys(&keys),"Invalid key generation, got {} vs {}",hex::encode(keys.displaykyberkey(false)),hex::encode(testkey.displaykyberkey(false)));
    }
}
