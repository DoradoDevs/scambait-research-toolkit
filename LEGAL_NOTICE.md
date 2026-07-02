# Legal Notice and Responsible-Use Guidelines

## Scambait Research Toolkit

**Version:** 1.0

> **Licensing note.** The *software itself* is released under the permissive
> [MIT License](LICENSE) - you are free to use, copy, modify, and redistribute
> the code. This document is **not** a license and does not restrict your rights
> under MIT. It is a set of responsible-use guidelines and ethics notes for
> a dual-use security-research tool. Where this document says "prohibited" or
> "authorized," it describes conduct we ask you not to engage in, not
> restrictions on the code grant.

---

## 1. Purpose and Scope

This software ("Scambait Research Toolkit") is a research tool intended for the
study and documentation of online fraud tactics. It is designed with users such
as the following in mind:

- Academic researchers studying cybercrime
- Security professionals conducting authorized research
- Law enforcement agencies (with appropriate jurisdiction)
- Corporate security teams conducting fraud awareness training

---

## 2. Authorized Use Cases

### 2.1 Permitted Activities

- Documenting scam communication patterns
- Analyzing malicious attachments in isolated environments
- Studying social engineering techniques
- Creating educational materials about fraud prevention
- Training security personnel to recognize scam tactics
- Reporting fraud to appropriate authorities

### 2.2 Discouraged / Out-of-Scope Activities

These are things we strongly ask you not to do with this tool. They are ethics
guidelines, not restrictions on the MIT-licensed code:

- Initiating unsolicited contact with non-consenting individuals
- Collecting personally identifiable information (PII) without a lawful basis
- Sharing any PII you collect about third parties outside a legitimate research
  or reporting context
- Using the tool for harassment, threats, or intimidation
- Any activity that violates applicable laws or regulations

---

## 3. Data Handling Policy

### 3.1 Data Collection

This tool may collect and store:
- IP addresses and network metadata
- Communication timestamps and patterns
- File hashes and analysis results
- Session interaction logs

### 3.2 Data Retention

- All data is stored locally only
- No data is transmitted externally
- Researchers should establish retention policies per their institutional guidelines
- Built-in wipe functionality supports data destruction requirements

### 3.3 Data Security

- All data stored in local SQLite database
- No cloud synchronization or external backups
- Uploaded files quarantined in isolated directory
- Audit logging tracks all data access

---

## 4. Compliance Framework

### 4.1 Audit Trail

The system maintains comprehensive audit logs including:
- All user actions with timestamps
- Session creation and modification events
- Data access and export activities
- System configuration changes

### 4.2 Export for Review

Audit logs can be exported in JSON format for:
- Internal compliance review
- Legal discovery requirements
- Institutional oversight

---

## 5. Ethical Guidelines

### 5.1 Research Ethics

Users conducting academic research should:
- Obtain IRB approval where required
- Document research methodology
- Maintain participant confidentiality where applicable
- Follow institutional data handling policies

### 5.2 Engagement Rules

When interacting with suspected scammers:
- Do not make threats or use abusive language
- Do not impersonate law enforcement
- Do not attempt to "hack back" or retaliate
- Document interactions for research purposes only

---

## 6. Liability Disclaimer

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.

IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

Users assume all responsibility for ensuring their use complies with applicable laws and regulations in their jurisdiction.

---

## 7. Incident Response

### 7.1 If You Discover Criminal Activity

If research reveals evidence of serious criminal activity:
1. Document findings using the export feature
2. Contact appropriate law enforcement
3. Preserve evidence following chain-of-custody guidelines
4. Consult with legal counsel as appropriate

### 7.2 Security Incidents

If the research environment is compromised:
1. Disconnect from any networks immediately
2. Use VM reset/wipe functionality
3. Document the incident
4. Report to your security team

---

## 8. Version Control

This document should be reviewed and updated:
- Annually at minimum
- When significant software changes occur
- When regulatory requirements change
- Following any compliance incidents

---

## 9. Acknowledgment

By using this software, you acknowledge that you have read, understood, and agree to comply with this Legal Notice and all applicable laws and regulations.

---

**For questions about compliance or authorized use, consult with your institution's legal or compliance department.**
