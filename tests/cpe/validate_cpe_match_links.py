import pyarrow.parquet as pq

criteria_path = "data/processed/cpe_match_criteria.parquet"
names_path = "data/processed/cpe_match_names.parquet"

print("Reading criteria IDs...")
criteria_file = pq.ParquetFile(criteria_path)
criteria_ids = set()

for batch in criteria_file.iter_batches(batch_size=100000, columns=["matchCriteriaId"]):
    criteria_ids.update(batch.column(0).to_pylist())

print(f"Unique criteria IDs loaded: {len(criteria_ids):,}")
print("Checking CPE-name associations...")

names_file = pq.ParquetFile(names_path)
total = 0
missing = 0
null_ids = 0
linked_criteria = set()

for batch in names_file.iter_batches(batch_size=100000, columns=["matchCriteriaId"]):
    values = batch.column(0).to_pylist()
    total += len(values)

    for value in values:
        if value is None:
            null_ids += 1
        elif value not in criteria_ids:
            missing += 1
        else:
            linked_criteria.add(value)

print("\nREFERENTIAL INTEGRITY RESULTS")
print(f"Total CPE-name associations: {total:,}")
print(f"Associations with missing criteria IDs: {missing:,}")
print(f"Associations with null criteria IDs: {null_ids:,}")
print(f"Unique criteria IDs linked to CPE names: {len(linked_criteria):,}")
print(f"Criteria with no linked CPE names: {len(criteria_ids - linked_criteria):,}")
print("RESULT:", "PASS" if missing == 0 and null_ids == 0 else "CHECK REQUIRED")
