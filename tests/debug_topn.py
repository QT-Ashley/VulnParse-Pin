import json

with open("example2_fixed.json") as f:
    data = json.load(f)

# Check number of assets in scan
print(f"Total assets in scan: {len(data['assets'])}")
print(f"Asset IDs: {[a['ip_address'] for a in data['assets']]}")

# Check findings per asset
for i, asset in enumerate(data['assets']):
    print(f"  Asset {i}: {len(asset['findings'])} findings")

# Check TopN
topn_data = data['derived']['passes']['TopN@1.0']['data']
print(f"\nAssets in TopN: {len(topn_data['assets'])}")
print(f"TopN asset IDs: {[a['asset_id'] for a in topn_data['assets']]}")
print(f"TopN k={topn_data['k']}, rank_basis={topn_data['rank_basis']}")

# Check scoring
scoring_data = data['derived']['passes']['Scoring@2.0']['data']
print(f"\nScored findings: {len(scoring_data['scored_findings'])}")
print(f"Asset scores: {scoring_data['asset_scores']}")
