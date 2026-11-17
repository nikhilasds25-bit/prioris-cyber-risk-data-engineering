# PRIORIS - CPE Data Processing



## 1. Overview



This component processes the National Vulnerability Database (NVD) CPE Dictionary 2.0 and CPE Match 2.0 datasets.



The objective is to transform large JSON datasets into structured Parquet files for efficient querying and integration with the PRIORIS PySpark vulnerability-processing pipeline.



## 2. Data Sources



### NVD CPE Dictionary 2.0



\- Source: https://nvd.nist.gov/feeds/json/cpe/2.0/nvdcpe-2.0.zip

\- Metadata: https://nvd.nist.gov/feeds/json/cpe/2.0/nvdcpe-2.0.meta

\- Chunks processed: 18

\- Records processed: 1,876,425



### NVD CPE Match 2.0



\- Source: https://nvd.nist.gov/feeds/json/cpematch/2.0/nvdcpematch-2.0.zip

\- Metadata: https://nvd.nist.gov/feeds/json/cpematch/2.0/nvdcpematch-2.0.meta

\- Chunks processed: 75

\- Criteria records: 677,659

\- CPE-name associations: 32,175,781



## 3. Processing Approach



The processing scripts use:



\- \*\*ijson:\*\* Streaming large JSON files without loading the complete dataset into memory.

\- \*\*PyArrow:\*\* Batch-based Parquet generation.

\- \*\*SQLite:\*\* Disk-backed duplicate identifier checks.

\- \*\*Python logging:\*\* Processing logs and error reporting.



The pipeline processes individual JSON chunks and writes records in batches to manage memory consumption.



## 4. Generated Outputs



### 4.1 cpe\_dictionary.parquet



Contains 1,876,425 CPE dictionary records.



Fields:



\- cpeName

\- cpeNameId

\- deprecated

\- created

\- lastModified

\- titles

\- deprecatedBy

\- deprecates

\- refs



Nested metadata is retained for titles, deprecation relationships, and references.



### 4.2 cpe\_match\_criteria.parquet



Contains 677,659 CPE match criteria records.



Fields:



\- matchCriteriaId

\- criteria

\- status

\- created

\- lastModified

\- cpeLastModified

\- versionStartIncluding

\- versionStartExcluding

\- versionEndIncluding

\- versionEndExcluding



### 4.3 cpe\_match\_names.parquet



Contains 32,175,781 CPE-name associations.



Fields:



\- matchCriteriaId

\- cpeName

\- cpeNameId



The `matchCriteriaId` field connects each association to its corresponding CPE Match criteria record.



## 5. Important Data Handling



\- Criteria records are preserved even when they have no CPE-name associations.

\- Version boundary fields are retained separately.

\- Dictionary metadata, including deprecation relationships, is preserved.

\- Duplicate identifiers are checked during processing.

\- Criteria and CPE-name associations are stored separately to avoid repeating criteria information for every associated CPE name.



## 6. Validation Results



| Validation | Result |

|---|---:|

| Dictionary records | 1,876,425 |

| Criteria records | 677,659 |

| CPE-name associations | 32,175,781 |

| Duplicate dictionary IDs | 0 |

| Duplicate criteria IDs | 0 |

| Missing criteria references | 0 |

| Null criteria references | 0 |

| Referential integrity | PASS |



A total of 218,392 criteria records have no CPE-name associations. These records are retained in the criteria output.



## 7. Reproducibility



The following files support reproducibility:



\- `requirements.txt` – Python dependencies and versions.

\- `manifests/cpe\_processing\_manifest.json` – Source metadata, checksums, processing counts, and validation results.

\- `src/process\_cpe\_dictionary.py` – Dictionary processing script.

\- `src/process\_cpe\_match.py` – CPE Match processing script.

\- `tests/validate\_cpe\_match\_links.py` – Referential-integrity validation script.



## 8. Running the Pipeline



Install dependencies:



```powershell

pip install -r requirements.txt

```



Process the CPE Dictionary:



```powershell

python src/process\_cpe\_dictionary.py

```



Process CPE Match:



```powershell

python src/process\_cpe\_match.py

```



Validate CPE Match relationships:



```powershell

python tests/validate\_cpe\_match\_links.py

```



## 9. Integration with PRIORIS



The generated Parquet files are intended for use in the main PRIORIS PySpark pipeline.



The `matchCriteriaId` field connects NVD CVE configuration criteria with corresponding CPE Match records.



The associated CPE names and identifiers can then be related to entries in the CPE Dictionary.



Together, these datasets provide standardized product identification and matching information for the vulnerability-to-asset matching stage.

## 10. Downloading the Processed Parquet Datasets

The full processed Parquet outputs are hosted in Google Drive rather than committed to Git, because the files are large.

**Shared dataset folder:** https://drive.google.com/drive/folders/1hexhYeA95TEVwVs4YQlICWw3W6bXL0tB?usp=sharing

The folder contains:

| File | Records | Approximate size |
|---|---:|---:|
| `cpe_dictionary.parquet` | 1,876,425 | 135 MB |
| `cpe_match_criteria.parquet` | 677,659 | 46 MB |
| `cpe_match_names.parquet` | 32,175,781 | 1.19 GB |

Access is restricted to invited Google accounts. Team members should open the folder using the Google account that was granted access, download the required files, and place them in the project's `data/processed/` directory before running the validation or integration scripts.

Do not commit the full Parquet files or raw NVD ZIP archives to the Git repository.
