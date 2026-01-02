#!/usr/bin/env python3
"""
Linux Security Auditor - AI-Enhanced Edition
Comprehensive security assessment with local LLM analysis
"""

import os
import pwd
import grp
import stat
import subprocess
import json
import re
import hashlib
import socket
import requests
from pathlib import Path
from datetime import datetime, timedelta
from typing import List, Dict, Tuple, Optional
from dataclasses import dataclass, asdict, field
import argparse

@dataclass
class SecurityIssue:
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    category: str
    title: str
    description: str
    affected_item: str
    recommendation: str
    cve_refs: Optional[List[str]] = None
    ai_analysis: Optional[str] = None
    ai_risk_score: Optional[float] = None
    
@dataclass
class AIAnalysisResult:
    risk_assessment: str
    attack_vectors: List[str]
    remediation_priority: str
    additional_context: str

class OllamaClient:
    """کلاینت برای ارتباط با Ollama"""
    
    def __init__(self, base_url="http://localhost:11434", model_coder="qwen2.5-coder:1.5b-base", 
                 model_chat="gemma3:1b-it-qat", timeout=30):
        self.base_url = base_url
        self.model_coder = model_coder
        self.model_chat = model_chat
        self.timeout = timeout
        self.available = self._check_availability()
        
    def _check_availability(self) -> bool:
        """چک کردن دسترسی به Ollama"""
        try:
            response = requests.get(f"{self.base_url}/api/tags", timeout=5)
            if response.status_code == 200:
                models = response.json().get('models', [])
                model_names = [m['name'] for m in models]
                
                # چک کردن وجود مدل‌ها
                has_coder = any(self.model_coder in m for m in model_names)
                has_chat = any(self.model_chat in m for m in model_names)
                
                if not has_coder:
                    print(f"⚠️  Model {self.model_coder} not found in Ollama")
                if not has_chat:
                    print(f"⚠️  Model {self.model_chat} not found in Ollama")
                    
                return has_coder or has_chat
            return False
        except Exception as e:
            print(f"⚠️  Ollama not available: {e}")
            return False
    
    def generate(self, prompt: str, use_coder: bool = False, system_prompt: str = None) -> Optional[str]:
        """ارسال prompt به Ollama و دریافت پاسخ"""
        if not self.available:
            return None
            
        model = self.model_coder if use_coder else self.model_chat
        
        try:
            payload = {
                "model": model,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": 0.3,  # کمتر برای پاسخ‌های consistent تر
                    "top_p": 0.9,
                }
            }
            
            if system_prompt:
                payload["system"] = system_prompt
            
            response = requests.post(
                f"{self.base_url}/api/generate",
                json=payload,
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                return response.json().get('response', '').strip()
            else:
                print(f"⚠️  Ollama error: {response.status_code}")
                return None
                
        except requests.exceptions.Timeout:
            print(f"⚠️  Ollama timeout for model {model}")
            return None
        except Exception as e:
            print(f"⚠️  Ollama error: {e}")
            return None

class AISecurityAnalyzer:
    """تحلیلگر امنیتی با AI"""
    
    def __init__(self, ollama_client: OllamaClient, verbose: bool = False):
        self.ollama = ollama_client
        self.verbose = verbose
        
    def analyze_security_issue(self, issue: SecurityIssue) -> Optional[AIAnalysisResult]:
        """تحلیل مشکل امنیتی با AI"""
        if not self.ollama.available:
            return None
        
        if self.verbose:
            print(f"[AI] Analyzing: {issue.title}")
        
        # ساخت prompt برای تحلیل
        prompt = f"""You are a security expert. Analyze this Linux security issue:

Category: {issue.category}
Severity: {issue.severity}
Issue: {issue.title}
Description: {issue.description}
Affected: {issue.affected_item}

Provide a brief analysis covering:
1. Real-world risk assessment (2-3 sentences)
2. Potential attack vectors (list 2-3)
3. Remediation priority (Immediate/High/Medium/Low)
4. Additional security context

Keep response concise and actionable."""

        system_prompt = """You are a Linux security expert specializing in vulnerability assessment and system hardening. 
Provide practical, actionable security analysis."""

        response = self.ollama.generate(prompt, use_coder=False, system_prompt=system_prompt)
        
        if not response:
            return None
        
        # پارس کردن پاسخ AI
        try:
            result = self._parse_ai_response(response)
            return result
        except Exception as e:
            if self.verbose:
                print(f"[AI] Parse error: {e}")
            return None
    
    def _parse_ai_response(self, response: str) -> AIAnalysisResult:
        """پارس کردن پاسخ AI"""
        lines = response.split('\n')
        
        risk_assessment = ""
        attack_vectors = []
        remediation_priority = "Medium"
        additional_context = ""
        
        current_section = None
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            lower_line = line.lower()
            
            # شناسایی بخش‌ها
            if 'risk' in lower_line or 'assessment' in lower_line:
                current_section = 'risk'
                continue
            elif 'attack' in lower_line or 'vector' in lower_line:
                current_section = 'vectors'
                continue
            elif 'priority' in lower_line or 'remediation' in lower_line:
                current_section = 'priority'
                continue
            elif 'context' in lower_line or 'additional' in lower_line:
                current_section = 'context'
                continue
            
            # اضافه کردن محتوا به بخش مناسب
            if current_section == 'risk':
                risk_assessment += line + " "
            elif current_section == 'vectors':
                if line.startswith('-') or line.startswith('•') or line[0].isdigit():
                    attack_vectors.append(line.lstrip('-•0123456789. '))
            elif current_section == 'priority':
                for priority in ['Immediate', 'High', 'Medium', 'Low']:
                    if priority.lower() in line.lower():
                        remediation_priority = priority
                        break
            elif current_section == 'context':
                additional_context += line + " "
        
        return AIAnalysisResult(
            risk_assessment=risk_assessment.strip() or "Risk assessment pending",
            attack_vectors=attack_vectors or ["Analysis in progress"],
            remediation_priority=remediation_priority,
            additional_context=additional_context.strip() or "See general recommendations"
        )
    
    def analyze_log_patterns(self, log_content: str, log_type: str) -> Optional[Dict]:
        """تحلیل pattern های لاگ با AI"""
        if not self.ollama.available:
            return None
        
        # محدود کردن لاگ برای AI
        log_lines = log_content.split('\n')[-100:]  # آخرین 100 خط
        log_sample = '\n'.join(log_lines)
        
        prompt = f"""Analyze these {log_type} log entries for security threats:

{log_sample}

Identify:
1. Suspicious patterns or anomalies
2. Potential security incidents
3. Attack signatures (brute force, scanning, etc)

Provide concise analysis (3-4 sentences)."""

        system_prompt = "You are a security analyst expert in log analysis and threat detection."
        
        response = self.ollama.generate(prompt, use_coder=False, system_prompt=system_prompt)
        
        if response:
            return {
                'analysis': response,
                'log_type': log_type,
                'lines_analyzed': len(log_lines)
            }
        return None
    
    def suggest_hardening_script(self, issues: List[SecurityIssue]) -> Optional[str]:
        """ساخت اسکریپت hardening با AI"""
        if not self.ollama.available or not issues:
            return None
        
        # انتخاب مهم‌ترین issues
        critical_issues = [i for i in issues if i.severity in ['CRITICAL', 'HIGH']][:10]
        
        if not critical_issues:
            return None
        
        issues_summary = "\n".join([
            f"- {i.category}: {i.title} -> {i.recommendation}"
            for i in critical_issues
        ])
        
        prompt = f"""Generate a bash hardening script to fix these security issues:

{issues_summary}

Create a safe, idempotent bash script with:
1. Backup of modified files
2. Clear comments
3. Error handling
4. Verification steps

Keep it under 50 lines and production-ready."""

        system_prompt = "You are a senior Linux system administrator. Generate safe, tested scripts."
        
        response = self.ollama.generate(prompt, use_coder=True, system_prompt=system_prompt)
        
        return response
    
    def calculate_risk_score(self, issue: SecurityIssue, ai_analysis: Optional[AIAnalysisResult]) -> float:
        """محاسبه risk score با ترکیب severity و AI analysis"""
        
        # Base score از severity
        severity_scores = {
            'CRITICAL': 10.0,
            'HIGH': 7.5,
            'MEDIUM': 5.0,
            'LOW': 2.5
        }
        
        base_score = severity_scores.get(issue.severity, 5.0)
        
        # اگه AI analysis داریم
        if ai_analysis:
            priority_multiplier = {
                'Immediate': 1.2,
                'High': 1.1,
                'Medium': 1.0,
                'Low': 0.9
            }
            
            multiplier = priority_multiplier.get(ai_analysis.remediation_priority, 1.0)
            
            # تعداد attack vectors هم مهمه
            vector_bonus = min(len(ai_analysis.attack_vectors) * 0.5, 2.0)
            
            final_score = min((base_score * multiplier) + vector_bonus, 10.0)
        else:
            final_score = base_score
        
        return round(final_score, 2)

class SecurityAuditor:
    def __init__(self, output_format='json', verbose=False, use_ai=True, 
                 ollama_url="http://localhost:11434"):
        self.issues = []
        self.output_format = output_format
        self.verbose = verbose
        self.timestamp = datetime.now().isoformat()
        self.hostname = socket.gethostname()
        
        # AI setup
        self.use_ai = use_ai
        if use_ai:
            self.ollama = OllamaClient(base_url=ollama_url)
            self.ai_analyzer = AISecurityAnalyzer(self.ollama, verbose=verbose)
            if not self.ollama.available:
                print("⚠️  AI analysis disabled - Ollama not available")
                self.use_ai = False
        else:
            self.ollama = None
            self.ai_analyzer = None
    
    @staticmethod
    def octal_to_chmod(octal_value):
        """تبدیل octal Python به format chmod"""
        # oct() returns '0o755', we need '755'
        return oct(octal_value)[2:]
        
    def log(self, message):
        """Print verbose logs"""
        if self.verbose:
            print(f"[DEBUG] {message}")
        
    def add_issue(self, severity, category, title, desc, item, recommendation, cve_refs=None):
        issue = SecurityIssue(severity, category, title, desc, item, recommendation, cve_refs)
        self.issues.append(issue)
    
    def enhance_issues_with_ai(self):
        """تحلیل issues با AI"""
        if not self.use_ai or not self.issues:
            return
        
        print(f"\n[*] Enhancing {len(self.issues)} issues with AI analysis...")
        
        # فقط CRITICAL و HIGH رو تحلیل می‌کنیم برای صرفه‌جویی در زمان
        priority_issues = [i for i in self.issues if i.severity in ['CRITICAL', 'HIGH']]
        
        analyzed_count = 0
        for issue in priority_issues[:15]:  # محدود به 15 تا
            ai_result = self.ai_analyzer.analyze_security_issue(issue)
            
            if ai_result:
                issue.ai_analysis = (
                    f"Risk: {ai_result.risk_assessment}\n"
                    f"Attack Vectors: {', '.join(ai_result.attack_vectors)}\n"
                    f"Priority: {ai_result.remediation_priority}\n"
                    f"Context: {ai_result.additional_context}"
                )
                
                issue.ai_risk_score = self.ai_analyzer.calculate_risk_score(issue, ai_result)
                analyzed_count += 1
        
        print(f"[+] AI analyzed {analyzed_count} critical issues")
    
    # [همان متدهای قبلی برای check ها...]
    
    def check_file_permissions(self):
        """بررسی permission های حساس"""
        print("[*] Checking sensitive file permissions...")
        
        sensitive_files = {
            '/etc/passwd': (0o644, 'root', 'root'),
            '/etc/shadow': (0o640, 'root', 'shadow'),
            '/etc/group': (0o644, 'root', 'root'),
            '/etc/gshadow': (0o640, 'root', 'shadow'),
            '/etc/ssh/sshd_config': (0o600, 'root', 'root'),
            '/root/.ssh/authorized_keys': (0o600, 'root', 'root'),
            '/etc/sudoers': (0o440, 'root', 'root'),
            '/boot/grub/grub.cfg': (0o600, 'root', 'root'),
            '/etc/fstab': (0o644, 'root', 'root'),
            '/etc/crontab': (0o600, 'root', 'root'),
        }
        
        for filepath, (expected_perm, expected_owner, expected_group) in sensitive_files.items():
            if not os.path.exists(filepath):
                self.log(f"Skipping {filepath} - not found")
                continue
                
            try:
                st = os.stat(filepath)
                actual_perm = stat.S_IMODE(st.st_mode)
                
                if actual_perm != expected_perm:
                    self.add_issue(
                        'HIGH',
                        'File Permissions',
                        'Incorrect permission on sensitive file',
                        f'File has permission {oct(actual_perm)} but should be {oct(expected_perm)}',
                        filepath,
                        f'chmod {oct(expected_perm)[2:]} {filepath}'  # حذف 0o از اول
                    )
                    
                try:
                    owner_info = pwd.getpwuid(st.st_uid)
                    group_info = grp.getgrgid(st.st_gid)
                    
                    if owner_info.pw_name != expected_owner:
                        self.add_issue(
                            'CRITICAL',
                            'File Ownership',
                            'Sensitive file not owned by correct user',
                            f'File owned by {owner_info.pw_name}, should be {expected_owner}',
                            filepath,
                            f'chown {expected_owner}:{expected_group} {filepath}'
                        )
                        
                    if group_info.gr_name != expected_group:
                        self.add_issue(
                            'HIGH',
                            'File Ownership',
                            'Sensitive file has incorrect group',
                            f'File group is {group_info.gr_name}, should be {expected_group}',
                            filepath,
                            f'chgrp {expected_group} {filepath}'
                        )
                except KeyError:
                    pass
                    
            except PermissionError:
                self.log(f"Permission denied reading {filepath}")
    
    def check_suid_sgid_files(self):
        """پیدا کردن فایل‌های SUID/SGID"""
        print("[*] Scanning for SUID/SGID files...")
        
        dangerous_paths = ['/tmp', '/home', '/var/tmp', '/dev/shm']
        known_safe = {
            '/usr/bin/sudo', '/usr/bin/passwd', '/usr/bin/chsh', 
            '/usr/bin/newgrp', '/usr/bin/su', '/usr/bin/mount', 
            '/usr/bin/umount', '/usr/bin/ping', '/usr/bin/chfn',
            '/usr/bin/gpasswd', '/usr/bin/fusermount',
        }
        
        for search_path in ['/', '/usr', '/bin', '/sbin']:
            if not os.path.exists(search_path):
                continue
                
            try:
                result = subprocess.run(
                    ['find', search_path, '-type', 'f', 
                     '(', '-perm', '-4000', '-o', '-perm', '-2000', ')', 
                     '-print'],
                    stdout=subprocess.PIPE, 
                    stderr=subprocess.DEVNULL,
                    text=True, 
                    timeout=120
                )
                
                for line in result.stdout.strip().split('\n'):
                    if not line or line in known_safe:
                        continue
                    
                    if any(line.startswith(p) for p in dangerous_paths):
                        self.add_issue(
                            'CRITICAL',
                            'SUID/SGID',
                            'SUID/SGID file in dangerous location',
                            'SUID/SGID executables in user-writable directories',
                            line,
                            f'chmod u-s,g-s {line}'
                        )
                    else:
                        self.add_issue(
                            'MEDIUM',
                            'SUID/SGID',
                            'Unknown SUID/SGID file',
                            'Verify if elevated privileges are required',
                            line,
                            f'Review and consider: chmod u-s,g-s {line}'
                        )
            except (subprocess.TimeoutExpired, FileNotFoundError):
                continue
    
    def check_ssh_config(self):
        """بررسی SSH"""
        print("[*] Auditing SSH configuration...")
        
        ssh_config = '/etc/ssh/sshd_config'
        if not os.path.exists(ssh_config):
            return
            
        try:
            with open(ssh_config, 'r') as f:
                config = f.read()
            
            checks = {
                'PermitRootLogin': ('yes', 'CRITICAL', 'no'),
                'PasswordAuthentication': ('yes', 'HIGH', 'no'),
                'PermitEmptyPasswords': ('yes', 'CRITICAL', 'no'),
                'X11Forwarding': ('yes', 'MEDIUM', 'no'),
            }
            
            for setting, (bad_value, severity, good_value) in checks.items():
                pattern = rf'^\s*{setting}\s+{bad_value}\s*$'
                if re.search(pattern, config, re.MULTILINE | re.IGNORECASE):
                    self.add_issue(
                        severity,
                        'SSH Configuration',
                        f'Insecure SSH: {setting}',
                        f'{setting} set to {bad_value}',
                        ssh_config,
                        f'Set {setting} {good_value}'
                    )
        except PermissionError:
            pass
    
    def check_nftables_rules(self):
        """بررسی firewall"""
        print("[*] Analyzing firewall rules...")
        
        try:
            result = subprocess.run(['nft', 'list', 'ruleset'], 
                                  stdout=subprocess.PIPE,
                                  stderr=subprocess.DEVNULL,
                                  text=True)
            ruleset = result.stdout
            
            if not ruleset.strip():
                self.add_issue(
                    'HIGH',
                    'Firewall',
                    'No firewall configured',
                    'System has no packet filtering',
                    'nftables',
                    'Configure nftables rules'
                )
                
        except FileNotFoundError:
            self.add_issue(
                'CRITICAL',
                'Firewall',
                'No firewall installed',
                'System completely exposed',
                'packages',
                'Install nftables or iptables'
            )
    
    def check_log_files(self):
        """تحلیل logs با AI"""
        print("[*] Analyzing system logs...")
        
        log_files = {
            '/var/log/auth.log': 'Authentication',
            '/var/log/secure': 'Security (RHEL)',
        }
        
        ai_log_insights = []
        
        for log_file, log_type in log_files.items():
            if not os.path.exists(log_file):
                continue
            
            try:
                with open(log_file, 'r') as f:
                    lines = f.readlines()[-1000:]
                    content = ''.join(lines)
                
                # تحلیل معمولی
                failed_logins = len(re.findall(r'Failed password|authentication failure', 
                                              content, re.IGNORECASE))
                
                if failed_logins > 50:
                    self.add_issue(
                        'HIGH',
                        'Log Analysis',
                        f'High failed login attempts: {failed_logins}',
                        'Possible brute force attack',
                        log_file,
                        'Investigate and implement fail2ban'
                    )
                
                # تحلیل با AI
                if self.use_ai and failed_logins > 10:
                    ai_result = self.ai_analyzer.analyze_log_patterns(content, log_type)
                    if ai_result:
                        ai_log_insights.append(ai_result)
                        
            except PermissionError:
                pass
        
        # ذخیره نتایج AI
        if ai_log_insights:
            self.log_ai_insights = ai_log_insights
    
    def generate_hardening_script(self):
        """ساخت اسکریپت hardening با AI"""
        if not self.use_ai:
            return None
        
        print("[*] Generating AI-powered hardening script...")
        
        script = self.ai_analyzer.suggest_hardening_script(self.issues)
        
        if script:
            try:
                script_file = f'hardening_script_{datetime.now().strftime("%Y%m%d_%H%M%S")}.sh'
                with open(script_file, 'w') as f:
                    f.write("#!/bin/bash\n")
                    f.write("# AI-Generated Security Hardening Script\n")
                    f.write(f"# Generated: {datetime.now()}\n\n")
                    f.write(script)
                
                os.chmod(script_file, 0o750)
                print(f"[+] Hardening script saved: {script_file}")
                return script_file
            except Exception as e:
                self.log(f"Could not save hardening script: {e}")
        
        return None
    
    def generate_report(self):
        """تولید گزارش با AI insights"""
        print("\n" + "="*70)
        print("🤖 AI-ENHANCED SECURITY AUDIT REPORT")
        print("="*70)
        print(f"Hostname: {self.hostname}")
        print(f"Timestamp: {self.timestamp}")
        print(f"Total Issues: {len(self.issues)}")
        
        if self.use_ai and self.ollama and self.ollama.available:
            print("🧠 AI Analysis: ENABLED")
        else:
            print("⚠️  AI Analysis: DISABLED")
        
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        
        for issue in self.issues:
            severity_counts[issue.severity] += 1
        
        print(f"\n{'Severity Breakdown':^70}")
        print("-" * 70)
        print(f"🔴 CRITICAL: {severity_counts['CRITICAL']:>3} | 🟠 HIGH: {severity_counts['HIGH']:>3} | "
              f"🟡 MEDIUM: {severity_counts['MEDIUM']:>3} | 🟢 LOW: {severity_counts['LOW']:>3}")
        print("\n" + "="*70 + "\n")
        
        # نمایش issues با AI analysis
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            severity_issues = [i for i in self.issues if i.severity == severity]
            if not severity_issues:
                continue
            
            symbol = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢'}
            
            print(f"\n{symbol[severity]} {severity} ISSUES ({len(severity_issues)})")
            print("="*70 + "\n")
            
            for idx, issue in enumerate(severity_issues[:10], 1):  # محدود به 10 تا برای نمایش
                print(f"[{idx}] {issue.title}")
                print(f"    📁 Category: {issue.category}")
                print(f"    🎯 Affected: {issue.affected_item}")
                print(f"    📝 {issue.description}")
                print(f"    ✅ Fix: {issue.recommendation}")
                
                if issue.ai_analysis:
                    print(f"\n    🤖 AI ANALYSIS:")
                    for line in issue.ai_analysis.split('\n'):
                        print(f"       {line}")
                    if issue.ai_risk_score:
                        print(f"    📊 Risk Score: {issue.ai_risk_score}/10.0")
                print()
        
        # AI Log Insights
        if hasattr(self, 'log_ai_insights') and self.log_ai_insights:
            print("\n" + "="*70)
            print("🤖 AI LOG ANALYSIS INSIGHTS")
            print("="*70 + "\n")
            
            for insight in self.log_ai_insights:
                print(f"📋 {insight['log_type']} Logs ({insight['lines_analyzed']} lines)")
                print(f"   {insight['analysis']}\n")
        
        # ذخیره JSON
        if self.output_format == 'json':
            json_data = {
                'hostname': self.hostname,
                'timestamp': self.timestamp,
                'ai_enabled': self.use_ai,
                'summary': {
                    'total_issues': len(self.issues),
                    'severity_counts': severity_counts,
                },
                'issues': [asdict(i) for i in self.issues]
            }
            
            if hasattr(self, 'log_ai_insights'):
                json_data['ai_log_insights'] = self.log_ai_insights
            
            output_file = f'ai_security_audit_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
            try:
                with open(output_file, 'w') as f:
                    json.dump(json_data, f, indent=2)
                print(f"\n📄 JSON report: {output_file}")
            except:
                pass
        
        print("\n" + "="*70)
        print("End of AI-Enhanced Security Audit")
        print("="*70 + "\n")
    
    def run_full_audit(self):
        """اجرای audit کامل"""
        print("="*70)
        print("🛡️  AI-Enhanced Linux Security Auditor")
        print("="*70 + "\n")
        
        if os.geteuid() != 0:
            print("⚠️  WARNING: Run with sudo for complete audit\n")
        
        # بررسی‌های اصلی
        self.check_file_permissions()
        self.check_suid_sgid_files()
        self.check_ssh_config()
        self.check_nftables_rules()
        self.check_log_files()
        
        # تحلیل با AI
        if self.use_ai:
            self.enhance_issues_with_ai()
            hardening_script = self.generate_hardening_script()
        
        self.generate_report()

def main():
    parser = argparse.ArgumentParser(
        description='AI-Enhanced Linux Security Auditor',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Verbose output')
    parser.add_argument('--no-ai', action='store_true',
                       help='Disable AI analysis')
    parser.add_argument('--ollama-url', default='http://localhost:11434',
                       help='Ollama server URL')
    parser.add_argument('--format', choices=['json', 'text'], default='json',
                       help='Output format')
    
    args = parser.parse_args()
    
    auditor = SecurityAuditor(
        output_format=args.format,
        verbose=args.verbose,
        use_ai=not args.no_ai,
        ollama_url=args.ollama_url
    )
    
    auditor.run_full_audit()

if __name__ == '__main__':
    main()
