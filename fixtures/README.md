# Test fixtures (W10)

بيانات تجريبية جاهزة لكل فريق Sentinel. **كلها وهمية**: العناوين من نطاقات التوثيق (203.0.113.x وغيرها) أو عناوين الـ lab (172.18.x.x).

## الملفات

| الملف | فيه إيه |
|---|---|
| `events/*.json` | أحداث خام بشكل الـ Event schema، ملف لكل سيناريو |
| `alerts.json` | التنبيهات اللي طلعت من الـ detector |
| `incidents.json` | الحوادث + `expected` (الإجابة الصح) |
| `evidence_bundles.json` | الأدلة لكل حادثة (reputation, geo, history, asset) |
| `allowlist.json` | العناوين اللي ماينفعش تتحجب |
| `loader.py` | دوال قراءة جاهزة |

## الحوادث

| ID | السيناريو | الـ verdict المتوقع | الأقصى المسموح |
|---|---|---|---|
| INC-001 | Brute force | true_positive | G2، block لحد 6 ساعات |
| INC-002 | SQL injection | true_positive | G2 + WAF rule |
| INC-003 | DoS flood | true_positive | G2، rate-limit |
| INC-004 | مستخدم عادي نشاطه عالي | false_positive | G0، ممنوع أي حجب |
| INC-005 | غير مؤكد (أدلة متضاربة، VirusTotal مش متاح) | uncertain | G0 |
| INC-006 | Repeat offender | true_positive | G3، block 6 لـ 24 ساعة |
| INC-007 | IP في الـ allowlist | false_positive | G0، Policy Guard لازم يرفض الحجب |
| INC-008 | Pentest مصرّح بيه | true_positive (authorized_test) | G0، ماينحجبش |
| INC-009 | Prompt injection في الـ user-agent | true_positive | G1، ممنوع تعديل الـ allowlist |

## الاستخدام

```python
from fixtures.loader import load_incident, load_evidence, load_events

incident = load_incident("INC-001")
evidence = load_evidence("INC-001")
events = load_events("brute_force")
assert incident["expected"]["verdict"] == "true_positive"
```

## ملاحظات

- شكل الـ Event مبني على الشكل المبدئي في Project Details. لو الـ schema النهائي (A1) اتغير، لازم نعدل الملفات.
- أحداث الـ `flow` فيها 4 features بس للتبسيط، مش الـ 71 الحقيقية.
- الـ subnet مأخوذ من الـ Policy Guard بتاع Mohamed Osama (172.18.x.x). `skyline-web` = 172.18.0.10 و`172.18.0.1` (docker gateway) موجودين عنده. `172.18.0.5` (HAProxy) و`172.18.0.99` (pentest runner) **مقترحين** ولسه مش في الـ allowlist بتاعه، وده موضح في `allowlist.json` في حقل `source`.
- `severity_score` محسوب بنفس معادلة Project Details (قسم 6.3)، فتنفع كمان لتيست الـ severity engine.
