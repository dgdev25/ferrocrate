use ferro_core::authorization::inventory::MUTATION_INVENTORY;
use serde::Serialize;

#[derive(Serialize)]
struct Entry<'a> {
    id: &'a str,
    mediation_test: &'a str,
}

fn main() {
    ferro_core::authorization::inventory::validate_inventory(MUTATION_INVENTORY)
        .expect("unique complete inventory");
    let entries: Vec<_> = MUTATION_INVENTORY
        .iter()
        .map(|entry| Entry {
            id: entry.id,
            mediation_test: entry.mediation_test,
        })
        .collect();
    println!(
        "{}",
        serde_json::to_string(&entries).expect("bounded inventory")
    );
}
