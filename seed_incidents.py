
from app.database import get_incidents
from fixtures.loader import load_incidents

# "expected" هي الإجابة الصح للتيستات، مش جزء من بيانات الحادثة
docs = [{k: v for k, v in i.items() if k != "expected"} for i in load_incidents()]
col = get_incidents()
col.delete_many({})
col.insert_many(docs)
print(f"Seeded {len(docs)} incidents")