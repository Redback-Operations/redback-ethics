**Pull Request Ethics, Security & Compliance Checklist**  
*(Mandatory for all pull requests. This helps you develop professional habits required in industry and academia.)*

1. Nature of the contribution (select all that apply)  
   - [ ] Purely non-functional changes (documentation, formatting, tests, CI/CD, refactoring without behavioral change)  
   - [ ] Introduction or modification of cryptographic functions or security-critical code  
   - [ ] Collection, storage, transmission, or processing of personal data (PII, health data, biometric data, location, etc.)  
   - [ ] Use or processing of data belonging to children under 13 (or reasonably likely to include such data)  
   - [ ] Implementation or modification of AI/ML models (training, fine-tuning, inference, prompt engineering)  
   - [ ] Code interacting with external networks, APIs, or third-party services  

2. Security & responsible practice assessment  
   - [ ] No security, privacy, or ethical implications identified  
   - [ ] Potential security or privacy implications present (e.g., input validation, error handling, data exposure)  
   - [ ] High-risk implications (potential for unauthorized access, data leakage, bias, or legal non-compliance)

3. Relevant laws, regulations, and frameworks considered (list all that may apply, or if none, refer to content in D2L Ethics module)  
   Examples:  
   - Australian Privacy Act 1988 (Cth) & Privacy Amendment (Notifiable Data Breaches) Act 2017  
   - GDPR (EU), CCPA/CPRA (California), COPPA (US children’s privacy)  
   - University Human Research Ethics requirements (HREC/NHRMC)  
   - NIST Cybersecurity Framework / OWASP Top 10 / ASVS  
   - ISO/IEC 27001, NIST AI Risk Management Framework (AI RMF)  
   - Export controls (ITAR, EAR, Australian Defence Export Controls)  
   > 

4. Security and responsible engineering measures implemented (select and describe)  
   - [ ] Yes — specify below (e.g., input sanitization, prepared statements, least-privilege access, data minimization, anonymization, secure defaults, dependency scanning, bias audit, consent mechanism, etc.)  
   - [ ] Partially implemented — further review recommended  
   - [ ] No — measures appear necessary  
   - [ ] Not applicable  
   > 

5. Additional notes (optional)  
   Any references to secure coding guidelines followed (e.g., ISO27001, OWASP Secure Coding Practices, university security standards), vulnerability scans performed, or ethical review status.  
   > 

By submitting this pull request, I confirm I have considered the security, privacy, and ethical implications of my contribution in accordance with university policy and applicable legal and professional standards.

Thank you for helping maintain a secure and responsible codebase.