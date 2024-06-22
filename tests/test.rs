#[cfg(test)]
mod tests {
    use std::sync::mpsc::channel;
    use std::time::Duration;
    use std::thread;
    use pqx::*;
    #[test]
    fn agreement() {
        let (sender1, receiver1) = channel();
        let (sender2, receiver2) = channel();
        let thread = thread::spawn(move || {
            let bob_s = Combinedkey::default();
            let bob_p = Combinedpub::new(&bob_s);
            sender1.send(bob_p).unwrap();
            let cipher = receiver2.recv_timeout(Duration::new(60,0)).unwrap();
            let cipher = Combinedcipher::from(cipher);
            Combinedshared::new(bob_s, cipher).unwrap()
        });
        let alice_s = Combinedkey::default();
        let pubkey = receiver1.recv_timeout(Duration::new(60,0)).unwrap();
        let kyberelem = Combinedcipher::new(&alice_s,&pubkey).unwrap();
        sender2.send(kyberelem.getcipher()).unwrap();
        let shared = Combinedshared::getfromshared(kyberelem, pubkey, alice_s).unwrap().getshared(SHAREDSIZE::Med);
        let result = thread.join().unwrap().getshared(SHAREDSIZE::Med);
        assert!(shared==result,"Invalid shared, got {:#?} and {:#?}",shared,result);
        //println!("Valid shared, got {}",hex::encode(shared.get()))
    }
}
