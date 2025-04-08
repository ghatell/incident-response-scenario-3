# 🚨 Incident Reponse: Potential Impossible Travel

This scenario investigates a Microsoft Sentinel alert triggered by multiple potential "Impossible Travel" detections within Azure AD Sign-In Logs.

![ChatGPT Image Apr 8, 2025 at 05_20_55 PM](https://github.com/user-attachments/assets/8e9d9913-ddc5-48e7-8a6a-e5a3b8d8a848)

## 📝 **Explanation**  
Corporations often have strict policies prohibiting:  
- 🌍 Logging in from multiple geographic regions outside designated areas.  
- 🔄 Account sharing (a standard security measure).  
- 🛡️ Using non-corporate VPNs.  

This scenario detects unusual activity, such as logins from **multiple geographic regions** within a short time frame.  

Whenever a user logs into Azure or authenticates with their main Azure account, logs are created in the **"SigninLogs"** table and forwarded to the **Log Analytics workspace** used by Microsoft Sentinel (our SIEM).  

### **Detection Objective:**  
Trigger an alert in Sentinel if a user logs into more than **one location** within a 7-day time period. Not all alerts will indicate malicious activity, as some may be false positives.  

---

## 🚦 **Creating the Alert Rule (Potential Impossible Travel)**  
**Objective:**  
Set up a Sentinel **Scheduled Query Rule** in Log Analytics to detect users logging into multiple geographic regions.  

### **Rule Configuration Details:**  
1. **Trigger Conditions:**  
   - A user logs into two or more distinct locations within 7 days.  

2. **KQL Query:**

```kql
let TimePeriodThreshold = timespan(7d);
let NumberOfDifferentLocationAllowed = 1;
SigninLogs
| where TimeGenerated > ago(TimePeriodThreshold)
| summarize count() by UserPrincipalName, City = tostring(parse_json(LocationDetails).city), State = tostring(parse_json(LocationDetails).state), Country = tostring(parse_json(LocationDetails).countryOrRegion)
| project UserPrincipalName, City, State, Country
| summarize PotentialImpossibleTravelInstances = count() by UserPrincipalName
| where PotentialImpossibleTravelInstances > NumberOfDifferentLocationAllowed
```
<img width="1021" alt="log1" src="https://github.com/user-attachments/assets/f6b547fc-bcaa-4d78-8998-8df5c13a78a5" />

3. **Analytics Rule Settings:**  

   <img width="1428" alt="log2" src="https://github.com/user-attachments/assets/7ead73c8-3770-450b-8987-709c5efeddc9" />

5. **Entity Mappings:**  

 <img width="653" alt="log3" src="https://github.com/user-attachments/assets/ccccef91-62e8-4a7d-ad60-e8f2a9c4a5eb" />

---

## 🔍 Detection and Analysis

An initial analytics rule flagged **44 accounts** for potential impossible travel — an unusually high volume that made manual triage impractical.

<img width="1430" alt="log4" src="https://github.com/user-attachments/assets/1e8d8f81-760f-41ab-bd87-c1e5980f97f3" />

### ✅ Optimization

To reduce noise, the rule was modified to limit the scope to **logins from the last 24 hours** instead of 7 days. This allowed for quicker and more relevant investigation.

<img width="1424" alt="log5" src="https://github.com/user-attachments/assets/5ed2ef50-aaab-41af-9b19-d30e0055ac19" />

### 📊 Results (After Filtering)

After running the updated rule, only **2 accounts** remained flagged with potential impossible travel:

<img width="1021" alt="log6" src="https://github.com/user-attachments/assets/3e508b57-e0ae-4a80-9163-0d2a9d44385d" />

---

## 🗂️ Geo-Based Sign-In Review

**KQL Query:**

```kql
let TargetUserPrincipalName = "936158d7e14f6bd01ac6405dfbd7dadc73d4403d02dc63c4e3367686207935f7@lognpacific.com";
let TimePeriodThreshold = timespan(1d);
SigninLogs
| where TimeGenerated > ago(TimePeriodThreshold)
| where UserPrincipalName == TargetUserPrincipalName
| project TimeGenerated, UserPrincipalName, City = tostring(parse_json(LocationDetails).city), State = tostring(parse_json(LocationDetails).state), Country = tostring(parse_json(LocationDetails).countryOrRegion)
| order by TimeGenerated desc
```

### 🔎 Account 1:
**`936158d7e14f6bd01ac6405dfbd7dadc73d4403d02dc63c4e3367686207935f7@lognpacific.com`**

<img width="953" alt="log7" src="https://github.com/user-attachments/assets/162b945e-ed20-4bc0-b9d0-661534a82851" />

➡️ **Observation:** All locations are in **Colorado**, and most likely reflect travel within the state or VPN routing — not impossible travel.

---

**KQL Query:**

```kql
let TargetUserPrincipalName = "a16319be0e3004e6b36517ba20cc3bb70ffadf9e417c13d0b01d916f8c091963@lognpacific.com";
let TimePeriodThreshold = timespan(1d);
SigninLogs
| where TimeGenerated > ago(TimePeriodThreshold)
| where UserPrincipalName == TargetUserPrincipalName
| project TimeGenerated, UserPrincipalName, City = tostring(parse_json(LocationDetails).city), State = tostring(parse_json(LocationDetails).state), Country = tostring(parse_json(LocationDetails).countryOrRegion)
| order by TimeGenerated desc
```

### 🔎 Account 2:
**`a16319be0e3004e6b36517ba20cc3bb70ffadf9e417c13d0b01d916f8c091963@lognpacific.com`**

<img width="977" alt="log8" src="https://github.com/user-attachments/assets/02a3b5c9-ef59-4a5c-8b76-43eca70d8fa7" />


➡️ **Observation:** All U.S.-based logins from expected locations. Timing suggests VPN use or cloud routing, not unauthorized travel.

---

## 🧠 Root Cause

The "Impossible Travel" rule misfired due to:

- **VPN/proxy traffic** appearing as distant locations.
- **Cloud-based login services** making it seem like simultaneous logins occurred across states.
- Lack of a **geo-velocity correlation** check in the original query.

---

## 🧹 Response and Mitigation

- 🧪 **False Positive** confirmed. No malicious activity was observed.
- 🛡️ **Rule refined** to include a threshold for geo-distance and velocity.
- 📘 **Documentation updated** to clarify expected behavior from VPN-influenced logins.

---

## 🛠️ **Containment, Eradication, and Recovery**  

- **Outcome:**  
   The alert was determined to be a **Benign Positive**:  
   - Both accounts logged in from **U.S.-based cities** that were either within the same state or plausible given typical user activity.  
   - The behavior was consistent with known VPN usage or expected travel patterns.

- **Next Steps:**  
   - 🔍 Monitored additional activity for the flagged accounts and verified no anomalies beyond the geographic locations.  
   - No indicators of compromise were observed, so **no containment or user restrictions** were applied.  

---

## 🔄 **Post-Incident Activities**  
1. **Rule Tuning:**  
   - Refined the impossible travel detection rule to **limit log scope to 24 hours**, reducing noise and enabling better triage.  
2. **User Context Enrichment:**  
   - Proposed integration of **VPN awareness** into rule logic for future iterations.  

---

## ✅ **Closure**  
1. **Review Incident:**  
   - Confirmed resolution and documented evidence supporting a **false positive** classification.  
   - Marked the incident as **Benign Positive**.  
2. **Report Finalization:**  
   - Submitted the post-incident review and updated the Sentinel incident log.

📌 **Status:** Closed as **Benign Positive**.

---

**✨ Lessons Learned:**  
- VPN and proxy traffic can significantly impact geo-based detection logic.  
- Fine-tuning timeframes and thresholds is essential for reducing false positives.  
- Enriching logs with contextual data like user role, travel status, or VPN use improves investigation efficiency.

📈 **Keep tuning, keep learning.** 🛡️
