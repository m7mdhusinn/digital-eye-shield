import os
import json
import base64
from fastapi import FastAPI, Depends, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
import models
from database import engine, get_db
from pydantic import BaseModel
from dotenv import load_dotenv
from groq import Groq

load_dotenv()

# تهيئة عميل Groq باستخدام المفتاح السحابي
groq_client = Groq(api_key=os.getenv("GROQ_API_KEY"))

models.Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Digital Eye (Cyber Shield AI) - Cloud Edition",
    description="نظام العين الرقمية الهجين لمكافحة الجرائم المعلوماتية والاحتيال المالي (سحابي)",
    version="2.1.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class URLScanRequest(BaseModel):
    url: str

class ContactScanRequest(BaseModel):
    contact: str

class BlockContactRequest(BaseModel):
    contact: str

@app.get("/")
def read_root():
    return {"status": "active", "message": "Digital Eye (Cyber Shield AI) Cloud Engine is running successfully!"}

# 1. مسار فحص الروابط سحابياً عبر Groq
@app.post("/api/v1/scan-url")
def scan_url(data: URLScanRequest, db: Session = Depends(get_db)):
    target_url = data.url.strip()
    risk_score = 0
    indicators = []
    
    dangerous_patterns = ["login", "verify", "update", "bank", "secure", "account", "signin", "wallet", "free", "prize", "win", "claim", "support", "stc"]
    matched_keywords = [kw for kw in dangerous_patterns if kw in target_url.lower()]
    
    if matched_keywords:
        risk_score += 40
        indicators.append(f"كلمات مفتاحية مريبة تم رصدها: {', '.join(matched_keywords)}")
        
    if "@" in target_url or target_url.count('.') > 3 or "http://" in target_url or "-" in target_url:
        risk_score += 30
        indicators.append("هيكل الرابط يحتوي على علامات تلاعب أو استخدام شرطات مريبة أو غير مشفر.")

    ai_expert_opinion = "تم تقييم الرابط عبر الفحص البرمجي."
    try:
        prompt_content = (
            f"أنت كبير محققي الأمن السيبراني ومختص كشف التصيد الاحتيالي (Phishing).\n"
            f"الرابط المراد فحصه: {target_url}\n"
            f"أجب بصيغة JSON فقط بالشكل التالي بدون أي نصوص خارجية:\n"
            f'{{"is_suspicious": true أو false, "confidence": نسبة الخطورة من 0 إلى 100, "reason": "التحليل التقني الدقيق باختصار باللغة العربية"}}'
        )
        
        completion = groq_client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[{"role": "user", "content": prompt_content}],
            response_format={"type": "json_object"}
        )
        
        res_json = completion.choices[0].message.content
        ai_data = json.loads(res_json)
        if ai_data.get("is_suspicious", False):
            risk_score = max(risk_score, ai_data.get("confidence", 80))
            ai_expert_opinion = ai_data.get("reason", "رصد نموذج الذكاء الاصطناعي مؤشرات خطورة عالية.")
        else:
            ai_expert_opinion = ai_data.get("reason", "الرابط يبدو سليماً ولا توجد مؤشرات تلاعب واضحة.")
    except Exception as e:
        ai_expert_opinion = f"التحليل يعمل بقواعد الحماية الاحتياطية (خطأ اتصال: {str(e)})"

    status = "Safe"
    if risk_score >= 30: status = "Suspicious"
    if risk_score >= 70: status = "Dangerous"

    db_log = models.ScanLog(target_type="url", target_value=target_url, risk_score=float(risk_score), status=status)
    db.add(db_log)
    db.commit()
    db.refresh(db_log)

    return {
        "scan_id": db_log.id, "url": target_url, "risk_score": risk_score,
        "status": status, "analysis_notes": indicators, "ai_expert_opinion": ai_expert_opinion, "scanned_at": db_log.created_at
    }

# 2. مسار فحص المستندات والإيصالات سحابياً
@app.post("/api/v1/scan-document")
async def scan_document(file: UploadFile = File(...), db: Session = Depends(get_db)):
    if not file:
        raise HTTPException(status_code=400, detail="لم يتم إرفاق أي ملف.")
    
    filename = file.filename
    content_bytes = await file.read()
    risk_score = 15
    indicators = [f"تم استلام المستند: {filename} بنجاح."]
    
    valid_extensions = [".jpg", ".jpeg", ".png", ".pdf", ".txt", ".csv"]
    ext = os.path.splitext(filename)[1].lower()
    if ext not in valid_extensions:
        risk_score += 60
        indicators.append("امتداد الملف غير معتمد نهائياً ويُعد مؤشراً خطيراً.")
    else:
        indicators.append("امتداد الملف نظامي ومتوافق.")
        
    file_text = f"حجم الملف: {len(content_bytes)} بايت."
    if ext in [".txt", ".csv"]:
        try:
            file_text += " المحتوى النصي: " + content_bytes.decode("utf-8", errors="ignore")[:300]
        except:
            pass

    ai_doc_opinion = "تمت مراجعة المستند برمجياً وسحابياً."
    try:
        prompt_content = (
            f"أنت خبير أدلة جنائية رقمية ومحقق في تزوير الإيصالات المالية والمستندات الرسمية.\n"
            f"اسم الملف: {filename}\n"
            f"التفاصيل: {file_text}\n"
            f"أجب بصيغة JSON فقط بدون أي نصوص خارجية:\n"
            f'{{"is_fake": true أو false, "risk_level": نسبة الخطورة من 0 إلى 100, "assessment": "تقرير المحقق الجنائي باللغة العربية"}}'
        )
        
        completion = groq_client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[{"role": "user", "content": prompt_content}],
            response_format={"type": "json_object"}
        )
        
        res_json = completion.choices[0].message.content
        ai_data = json.loads(res_json)
        risk_score = max(risk_score, ai_data.get("risk_level", 30))
        ai_doc_opinion = ai_data.get("assessment", "تحليل مستندات دقيق عبر الذكاء الاصطناعي السحابي.")
    except Exception as e:
        ai_doc_opinion = f"الاعتماد على الفحص المبدئي (خطأ بالنموذج السحابي: {str(e)})"

    status = "Safe"
    if risk_score >= 30: status = "Suspicious"
    if risk_score >= 70: status = "Dangerous"

    db_log = models.ScanLog(target_type="document", target_value=filename, risk_score=float(risk_score), status=status)
    db.add(db_log)
    db.commit()
    db.refresh(db_log)

    return {
        "scan_id": db_log.id, "filename": filename, "risk_score": risk_score,
        "status": status, "analysis_notes": indicators, "ai_document_review": ai_doc_opinion, "scanned_at": db_log.created_at
    }

# 3. مسار فحص أرقام واتساب والمعرفات سحابياً
@app.post("/api/v1/scan-contact")
def scan_contact(data: ContactScanRequest, db: Session = Depends(get_db)):
    target_contact = data.contact.strip()
    risk_score = 10
    indicators = []
    
    previous_reports = db.query(models.ScanLog).filter(
        models.ScanLog.target_type == "contact",
        models.ScanLog.target_value == target_contact
    ).count()
    
    if previous_reports > 0:
        risk_score += 75
        indicators.append(f"تحذير أمني خطير: تم رصد {previous_reports} بلاغات سابقة مسجلة ضد هذا الرقم محلياً!")
    else:
        indicators.append("الرقم أو المعرف غير مسجل مسبقاً في سجل الحظر المحلي.")

    fraud_keywords = [
        "admin", "support", "bank", "stc", "mobily", "zain", "absher", "sadaia", 
        "prize", "win", "winner", "free", "service", "update", "verify", "wallet",
        "الراجحي", "الأهلي", "الإنماء", "البنك", "دعم", "مسابقة", "مكافأة", "تحديث", "إيقاف"
    ]
    
    matched_suspicious_words = [word for word in fraud_keywords if word in target_contact.lower()]
    if matched_suspicious_words:
        risk_score += 50
        indicators.append(f"تم رصد مصطلحات رسمية مستخدمة في الاحتيال وانتحال الصفة: {', '.join(matched_suspicious_words)}")
        
    if target_contact.startswith("+"):
        if len(target_contact) > 13 or target_contact.startswith("+0") or target_contact.startswith("+99"):
            risk_score += 30
            indicators.append("رقم دولي مريب أو بمفتاح تشغيل غير معتاد للاستخدام الشخصي.")
        else:
            indicators.append("رقم دولي نظامي معتمد.")
    elif "@" in target_contact:
        indicators.append("معرف حساب تواصل اجتماعي يتطلب الحذر عند التعامل المالي.")

    ai_contact_opinion = "تم فحص المعرف عبر قواعد الفحص البرمجي."
    try:
        prompt_content = (
            f"أنت رئيس وحدة مكافحة الجرائم الإلكترونية واحتيال المالي.\n"
            f"المعرف أو الرقم المراد فحصه: {target_contact}\n"
            f"مؤشرات تم رصدها برمجياً: {', '.join(indicators)}\n\n"
            f"قم بتحليل سلوك هذا المعرف أو الرقم بدقة. هل يمثل حساب عصابة احتيال تستهدف الضحايا؟\n"
            f"أجب بصيغة JSON فقط بدون أي مقدمات:\n"
            f'{{"is_fraud": true أو false, "risk_score": نسبة الخطورة الرقمية من 0 إلى 100, "reason": "تقرير المحقق الجنائي باللغة العربية"}}'
        )
        
        completion = groq_client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[{"role": "user", "content": prompt_content}],
            response_format={"type": "json_object"}
        )
        
        res_json = completion.choices[0].message.content
        ai_data = json.loads(res_json)
        if ai_data.get("is_fraud", False):
            risk_score = max(risk_score, ai_data.get("risk_score", 75))
            ai_contact_opinion = ai_data.get("reason", "رصد نموذج الذكاء الاصطناعي مؤشرات احتيال واضحة.")
        else:
            ai_expert_reason = ai_data.get("reason", "")
            ai_contact_opinion = ai_expert_reason if ai_expert_reason else "المعرف يبدو طبيعياً ولا توجد أدلة قاطعة على استخدامه في الاحتيال."
    except Exception as e:
        ai_contact_opinion = f"التحليل يعمل بنظام الحماية الاحتياطية (خطأ اتصال سحابي: {str(e)})"

    status = "Safe"
    if risk_score >= 30: status = "Suspicious"
    if risk_score >= 70: status = "Dangerous"

    db_log = models.ScanLog(target_type="contact", target_value=target_contact, risk_score=float(risk_score), status=status)
    db.add(db_log)
    db.commit()
    db.refresh(db_log)

    return {
        "scan_id": db_log.id, "contact": target_contact, "risk_score": risk_score,
        "status": status, "analysis_notes": indicators, "ai_contact_review": ai_contact_opinion, "scanned_at": db_log.created_at
    }

# 4. مسار حظر الأرقام وإضافتها للقائمة السوداء
@app.post("/api/v1/block-contact")
def block_contact(data: BlockContactRequest, db: Session = Depends(get_db)):
    target_contact = data.contact.strip()
    db_log = models.ScanLog(target_type="contact", target_value=target_contact, risk_score=100.0, status="Dangerous")
    db.add(db_log)
    db.commit()
    return {"status": "success", "message": f"تم حظر الرقم أو المعرف ({target_contact}) وإضافته لقائمة التهديدات المؤكدة بنجاح."}

# 5. مسار جلب السجلات والبحث فيها
from sqlalchemy import or_
@app.get("/api/v1/scan-history")
def get_scan_history(search: str = None, db: Session = Depends(get_db)):
    query = db.query(models.ScanLog)
    if search:
        search_term = f"%{search.strip()}%"
        query = query.filter(
            or_(
                models.ScanLog.target_value.ilike(search_term),
                models.ScanLog.target_type.ilike(search_term),
                models.ScanLog.status.ilike(search_term)
            )
        )
    logs = query.order_by(models.ScanLog.created_at.desc()).limit(50).all()
    return logs

'''
import os
import json
import base64
import requests
from fastapi import FastAPI, Depends, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
import models
from database import engine, get_db
from pydantic import BaseModel
from dotenv import load_dotenv

load_dotenv()

models.Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Cyber Shield AI - Advanced Hybrid Engine",
    description="نظام هجين دقيق لمكافحة الجرائم المعلوماتية والاحتيال المالي",
    version="2.0.0"
)

# تفعيل الـ CORS للربط مع الواجهة الأمامية
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- تعريف النماذج (Pydantic Models) في البداية ---
class URLScanRequest(BaseModel):
    url: str

class ContactScanRequest(BaseModel):
    contact: str  # رقم جوال أو معرف واتساب/تيليجرام
# ---------------------------------------------

@app.get("/")
def read_root():
    return {"status": "active", "message": "Cyber Shield AI Advanced Hybrid Engine is running!"}

# 1. مسار فحص الروابط بالذكاء الاصطناعي الهجين والدقيق
@app.post("/api/v1/scan-url")
def scan_url(data: URLScanRequest, db: Session = Depends(get_db)):
    target_url = data.url.strip()
    risk_score = 0
    indicators = []
    
    dangerous_patterns = ["login", "verify", "update", "bank", "secure", "account", "signin", "wallet", "free", "prize", "win", "claim", "support", "stc"]
    matched_keywords = [kw for kw in dangerous_patterns if kw in target_url.lower()]
    
    if matched_keywords:
        risk_score += 40
        indicators.append(f"كلمات مفتاحية مريبة تم رصدها: {', '.join(matched_keywords)}")
        
    if "@" in target_url or target_url.count('.') > 3 or "http://" in target_url or "-" in target_url:
        risk_score += 30
        indicators.append("هيكل الرابط يحتوي على علامات تلاعب أو استخدام شرطات مريبة أو غير مشفر.")

    ai_expert_opinion = "تم تقييم الرابط عبر الفحص البرمجي."
    try:
        prompt_content = (
            f"أنت كبير محققي الأمن السيبراني ومختص كشف التصيد الاحتيالي (Phishing). قم بتحليل هذا الرابط بعين صارمة جداً:\n"
            f"الرابط: {target_url}\n"
            f"قواعد التقييم:\n"
            f"- أي رابط يحاول تقليد موقع رسمي بنطاق غريب أو فرعي يعتبر احتيالاً فورياً.\n"
            f"- أعطِ نسبة ثقة عالية إذا كان هناك أي شك في التمويه أو التصيد.\n"
            f"أجب بصيغة JSON فقط بدون أي مقدمات:\n"
            f'{{"is_suspicious": true أو false, "confidence": نسبة الخطورة الرقمية من 0 إلى 100, "reason": "التحليل التقني الدقيق باختصار"}}'
        )
        
        ollama_response = requests.post(
            "http://127.0.0.1:11434/api/generate",
            json={"model": "llama3", "prompt": prompt_content, "stream": False, "format": "json"},
            timeout=60
        )
        
        if ollama_response.status_code == 200:
            res_json = ollama_response.json().get("response", "{}")
            ai_data = json.loads(res_json)
            if ai_data.get("is_suspicious", False):
                risk_score = max(risk_score, ai_data.get("confidence", 80))
                ai_expert_opinion = ai_data.get("reason", "رصد نموذج الذكاء الاصطناعي مؤشرات خطورة عالية.")
            else:
                ai_expert_opinion = ai_data.get("reason", "الرابط يبدو سليماً ولا توجد مؤشرات تلاعب واضحة.")
    except Exception as e:
        ai_expert_opinion = f"التحليل يعمل بقواعد الحماية الاحتياطية (خطأ اتصال: {str(e)})"

    status = "Safe"
    if risk_score >= 30: status = "Suspicious"
    if risk_score >= 70: status = "Dangerous"

    db_log = models.ScanLog(target_type="url", target_value=target_url, risk_score=float(risk_score), status=status)
    db.add(db_log)
    db.commit()
    db.refresh(db_log)

    return {
        "scan_id": db_log.id, "url": target_url, "risk_score": risk_score,
        "status": status, "analysis_notes": indicators, "ai_expert_opinion": ai_expert_opinion, "scanned_at": db_log.created_at
    }

# 2. مسار فحص المستندات والإيصالات باستخدام نموذج الرؤية (llava)
@app.post("/api/v1/scan-document")
async def scan_document(file: UploadFile = File(...), db: Session = Depends(get_db)):
    if not file:
        raise HTTPException(status_code=400, detail="لم يتم إرفاق أي ملف.")
    
    filename = file.filename
    content_bytes = await file.read()
    risk_score = 15
    indicators = [f"تم استلام المستند: {filename} بنجاح."]
    
    valid_extensions = [".jpg", ".jpeg", ".png", ".pdf", ".txt", ".csv"]
    ext = os.path.splitext(filename)[1].lower()
    if ext not in valid_extensions:
        risk_score += 60
        indicators.append("امتداد الملف غير معتمد نهائياً ويُعد مؤشراً خطيراً.")
    else:
        indicators.append("امتداد الملف نظامي ومتوافق.")
        
    file_base64 = base64.b64encode(content_bytes).decode('utf-8')
    
    file_text = f"حجم الملف: {len(content_bytes)} بايت."
    if ext in [".txt", ".csv"]:
        try:
            file_text += " المحتوى النصي: " + content_bytes.decode("utf-8", errors="ignore")[:300]
        except:
            pass

    ai_doc_opinion = "تمت مراجعة المستند بصرياً."
    try:
        prompt_content = (
            f"أنت خبير أدلة جنائية رقمية ومحقق في تزوير الإيصالات المالية والمستندات الرسمية.\n"
            f"اسم الملف: {filename}\n"
            f"قم بتحليل هذه الصورة أو المستند بعين فاحصة للكشف عن التلاعب، فوتوشوب، أو إيصالات مزيفة.\n"
            f"أجب بصيغة JSON فقط بدون أي نصوص خارجية:\n"
            f'{{"is_fake": true أو false, "risk_level": نسبة الخطورة من 0 إلى 100, "assessment": "تقرير المحقق الجنائي المفصل باللغة العربية"}}'
        )
        
        ollama_response = requests.post(
            "http://127.0.0.1:11434/api/generate",
            json={
                "model": "llava",
                "prompt": prompt_content,
                "images": [file_base64],
                "stream": False,
                "format": "json"
            },
            timeout=90
        )
        
        if ollama_response.status_code == 200:
            res_json = ollama_response.json().get("response", "{}")
            ai_data = json.loads(res_json)
            risk_score = max(risk_score, ai_data.get("risk_level", 30))
            ai_doc_opinion = ai_data.get("assessment", "تحليل بصري دقيق للمستند عبر نموذج الرؤية الاصطناعي.")
    except Exception as e:
        ai_doc_opinion = f"الاعتماد على الفحص المبدئي (خطأ في تشغيل نموذج llava: {str(e)})"

    status = "Safe"
    if risk_score >= 30: status = "Suspicious"
    if risk_score >= 70: status = "Dangerous"

    db_log = models.ScanLog(target_type="document", target_value=filename, risk_score=float(risk_score), status=status)
    db.add(db_log)
    db.commit()
    db.refresh(db_log)

    return {
        "scan_id": db_log.id, "filename": filename, "risk_score": risk_score,
        "status": status, "analysis_notes": indicators, "ai_document_review": ai_doc_opinion, "scanned_at": db_log.created_at
    }

# 3. مسار فحص أرقام واتساب والمعرفات فائق الدقة
@app.post("/api/v1/scan-contact")
def scan_contact(data: ContactScanRequest, db: Session = Depends(get_db)):
    target_contact = data.contact.strip()
    risk_score = 10
    indicators = []
    
    previous_reports = db.query(models.ScanLog).filter(
        models.ScanLog.target_type == "contact",
        models.ScanLog.target_value == target_contact
    ).count()
    
    if previous_reports > 0:
        risk_score += 75
        indicators.append(f"تحذير أمني خطير: تم رصد {previous_reports} بلاغات سابقة مسجلة ضد هذا الرقم محلياً!")
    else:
        indicators.append("الرقم أو المعرف غير مسجل مسبقاً في سجل الحظر المحلي.")

    fraud_keywords = [
        "admin", "support", "bank", "stc", "mobily", "zain", "absher", "sadaia", 
        "prize", "win", "winner", "free", "service", "update", "verify", "wallet",
        "الراجحي", "الأهلي", "الإنماء", "البنك", "دعم", "مسابقة", "مكافأة", "تحديث", "إيقاف"
    ]
    
    matched_suspicious_words = [word for word in fraud_keywords if word in target_contact.lower()]
    if matched_suspicious_words:
        risk_score += 50
        indicators.append(f"تم رصد مصطلحات رسمية مستخدمة في الاحتيال وانتحال الصفة: {', '.join(matched_suspicious_words)}")
        
    if target_contact.startswith("+"):
        if len(target_contact) > 13 or target_contact.startswith("+0") or target_contact.startswith("+99"):
            risk_score += 30
            indicators.append("رقم دولي مريب أو بمفتاح تشغيل غير معتاد للاستخدام الشخصي.")
        else:
            indicators.append("رقم دولي نظامي معتمد.")
    elif "@" in target_contact:
        indicators.append("معرف حساب تواصل اجتماعي يتطلب الحذر عند التعامل المالي.")

    ai_contact_opinion = "تم فحص المعرف عبر قواعد الفحص البرمجي."
    try:
        prompt_content = (
            f"أنت رئيس وحدة مكافحة الجرائم الإلكترونية والاحتيال المالي.\n"
            f"المعرف أو الرقم المراد فحصه: {target_contact}\n"
            f"مؤشرات تم رصدها برمجياً: {', '.join(indicators)}\n\n"
            f"قم بتحليل سلوك هذا المعرف أو الرقم بدقة. هل يمثل حساب عصابة احتيال تستهدف الضحايا؟\n"
            f"أجب بصيغة JSON فقط بدون أي مقدمات:\n"
            f'{{"is_fraud": true أو false, "risk_score": نسبة الخطورة الرقمية من 0 إلى 100, "reason": "تقرير المحقق الجنائي الدقيق والمختصر باللغة العربية"}}'
        )
        
        ollama_response = requests.post(
            "http://127.0.0.1:11434/api/generate",
            json={"model": "llama3", "prompt": prompt_content, "stream": False, "format": "json"},
            timeout=60
        )
        
        if ollama_response.status_code == 200:
            res_json = ollama_response.json().get("response", "{}")
            ai_data = json.loads(res_json)
            if ai_data.get("is_fraud", False):
                risk_score = max(risk_score, ai_data.get("risk_score", 75))
                ai_contact_opinion = ai_data.get("reason", "رصد نموذج الذكاء الاصطناعي مؤشرات احتيال واضحة.")
            else:
                ai_expert_reason = ai_data.get("reason", "")
                ai_contact_opinion = ai_expert_reason if ai_expert_reason else "المعرف يبدو طبيعياً ولا توجد أدلة قاطعة على استخدامه في الاحتيال."
    except Exception as e:
        ai_contact_opinion = f"التحليل يعمل بنظام الحماية الاحتياطية (خطأ اتصال بالنموذج: {str(e)})"

    status = "Safe"
    if risk_score >= 30: status = "Suspicious"
    if risk_score >= 70: status = "Dangerous"

    db_log = models.ScanLog(target_type="contact", target_value=target_contact, risk_score=float(risk_score), status=status)
    db.add(db_log)
    db.commit()
    db.refresh(db_log)

    return {
        "scan_id": db_log.id, "contact": target_contact, "risk_score": risk_score,
        "status": status, "analysis_notes": indicators, "ai_contact_review": ai_contact_opinion, "scanned_at": db_log.created_at
    }
class BlockContactRequest(BaseModel):
    contact: str

@app.post("/api/v1/block-contact")
def block_contact(data: BlockContactRequest, db: Session = Depends(get_db)):
    target_contact = data.contact.strip()
    
    # التحقق مما إذا كان مسجلاً مسبقاً لتحديثه أو إضافة سجل حظر جديد
    db_log = models.ScanLog(
        target_type="contact",
        target_value=target_contact,
        risk_score=100.0,
        status="Dangerous"
    )
    db.add(db_log)
    db.commit()
    
    return {"status": "success", "message": f"تم حظر الرقم أو المعرف ({target_contact}) وإضافته لقائمة التهديدات المؤكدة بنجاح."}
from sqlalchemy import or_

@app.get("/api/v1/scan-history")
def get_scan_history(search: str = None, db: Session = Depends(get_db)):
    query = db.query(models.ScanLog)
    if search:
        search_term = f"%{search.strip()}%"
        query = query.filter(
            or_(
                models.ScanLog.target_value.ilike(search_term),
                models.ScanLog.target_type.ilike(search_term),
                models.ScanLog.status.ilike(search_term)
            )
        )
    # جلب أحدث السجلات أولاً
    logs = query.order_by(models.ScanLog.created_at.desc()).limit(50).all()
    return logs
    '''