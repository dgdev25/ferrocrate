use keyring::{Entry, Error};

#[test]
fn production_backend_is_not_mock() {
    let entry = Entry::new("ferrocrate-backend-selection-test", "no-secret").unwrap();
    assert!(
        entry
            .get_credential()
            .downcast_ref::<keyring::mock::MockCredential>()
            .is_none(),
        "desktop credentials must use a real platform store"
    );
}

#[test]
#[ignore = "requires the isolated Secret Service fixture"]
fn credentials_survive_new_entries_and_processes() {
    assert_eq!(
        std::env::var("FERROCRATE_PRIVATE_KEYRING_TEST").as_deref(),
        Ok("1")
    );
    let account = format!("disposable-{}", std::process::id());
    let service = "ferrocrate-isolated-persistence-test";
    let entry = Entry::new(service, &account).unwrap();
    entry.set_password("disposable-test-value").unwrap();
    drop(entry);
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "credential_child_read"])
        .env("FERROCRATE_KEYRING_TEST_ACCOUNT", &account)
        .status()
        .unwrap();
    let entry = Entry::new(service, &account).unwrap();
    let read = entry.get_password();
    entry.delete_credential().unwrap();
    assert!(
        status.success(),
        "separate process must read the stored secret"
    );
    assert_eq!(read.unwrap(), "disposable-test-value");
    assert!(matches!(
        Entry::new(service, &account).unwrap().get_password(),
        Err(Error::NoEntry)
    ));
}

#[test]
fn credential_child_read() {
    let Ok(account) = std::env::var("FERROCRATE_KEYRING_TEST_ACCOUNT") else {
        return;
    };
    assert_eq!(
        Entry::new("ferrocrate-isolated-persistence-test", &account)
            .unwrap()
            .get_password()
            .unwrap(),
        "disposable-test-value"
    );
}
