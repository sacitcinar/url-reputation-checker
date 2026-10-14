# Brand Catalog Import and Audit Status (V1.4)

Import date: 2026-10-14. **No new first-party brand-domain verification was performed.**

The previous 600-entry brand catalog has been replaced with the two user-supplied
JSON files, byte-for-byte. Both are valid arrays of {`name`, `domains`, `aliases`}
records and have no duplicate domains within each file.

- Global user catalog: **500** brand entries, 500 domain values.
- Turkey user catalog: **75** brand entries, 77 domain values.
- Separate V1.3 detection-compatibility signatures: **3** entries (PayPal, Google, GitHub).
- Combined available detection references: **578** entries. The supplemental records do *not* change the supplied JSON files.
- Source data has not been checked against official websites; it is not a verified whitelist. Exact official-domain handling is not proof that a website is harmless.

SHA-256 digests for the user-supplied catalogs:

```text
brands_global.json  19d8b542474168397ff6609b055923645e2d0682168291a0b9f000f1b25be581
brands_turkey.json  b983c1b25e799f5e50065ad5ae681dbc825b606bdc6b722a285e3d7706f63a44
```

`BRAND_VERIFICATION.csv` is a current inventory. Previous V1.3's 18 manually
checked brands do not transfer automatically to these newly supplied records;
therefore all imported rows are marked `user_supplied_unverified` until separately verified.
