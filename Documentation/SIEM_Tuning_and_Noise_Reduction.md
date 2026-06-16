# ProjectX SIEM Tuning Log

## Issue: MailHog Benchmarking Generating Alert Floods
* **Symptom:** Internal test automated delivery notifications on the Ubuntu Postfix/MailHog server generated 4,000+ Wazuh alerts daily under Rule 20003 (MTA connections).
* **Classification:** False Positive (Benign internal system traffic).
* **Action Taken:** Tuned the local rules manager to whitelist the specific IP address of the local mail relay (`10.0.0.15`), successfully dropping baseline daily log noise by 38%.
