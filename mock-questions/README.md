# KCSA Mock Exam Collection

## Overview

This directory contains comprehensive mock examinations designed to help you prepare for the Kubernetes and Cloud Native Security Associate (KCSA) certification exam. These practice tests simulate the actual exam environment and cover all domains of the KCSA curriculum.

## Exam Structure

Each mock exam consists of:
- **Total Questions**: 60 questions
- **Duration**: 90 minutes
- **Passing Score**: 75% (45 out of 60 questions)
- **Format**: Multiple choice with 4 options per question
- **Question Type**: Scenario-based, practical questions

## Domain Distribution

Questions are distributed across the six KCSA domains:

| Domain | Topic | Questions per Exam |
|--------|-------|-------------------|
| Domain 1 | Overview of Cloud Native Security | 6 questions |
| Domain 2 | Kubernetes Cluster Component Security | 12 questions |
| Domain 3 | Kubernetes Security Fundamentals | 9 questions |
| Domain 4 | Kubernetes Threat Model | 12 questions |
| Domain 5 | Platform Security | 12 questions |
| Domain 6 | Compliance and Security Frameworks | 9 questions |

## Available Mock Exams

### Mock Exam Set 1
**File**: [mock-exam-set-1.md](mock-exam-set-1.md)

**Focus**: Comprehensive coverage of all domains with balanced difficulty
- Tests fundamental understanding of security concepts
- Scenario-based questions simulating real-world situations
- Mix of knowledge recall and application
- **Difficulty**: 30% Easy, 50% Medium, 20% Hard

**Best For**: First practice exam, baseline assessment

### Mock Exam Set 2
**File**: [mock-exam-set-2.md](mock-exam-set-2.md)

**Focus**: Advanced scenarios and edge cases
- Complex multi-step scenarios
- Troubleshooting and problem-solving focus
- Integration between multiple security concepts
- **Difficulty**: 20% Easy, 50% Medium, 30% Hard

**Best For**: Advanced preparation, identifying knowledge gaps

### Mock Exam Set 3
**File**: [mock-exam-set-3.md](mock-exam-set-3.md)

**Focus**: Common exam traps and gotchas
- Questions designed around common misconceptions
- Edge cases and nuanced differences
- Detailed explanations of why wrong answers are incorrect
- **Difficulty**: 25% Easy, 50% Medium, 25% Hard

**Best For**: Final preparation, avoiding common mistakes

## How to Use These Mock Exams

### Taking the Exam

1. **Time Yourself**: Set a 90-minute timer and take the exam in one sitting
2. **No Resources**: Don't use documentation or external resources during the exam
3. **Mark Your Answers**: Write down your answers (A, B, C, or D) for each question
4. **Review Carefully**: Read each question thoroughly before answering
5. **Flag Uncertain**: Mark questions you're unsure about for review

### After the Exam

1. **Check Your Answers**: Compare your answers with the correct answers in the answer key
2. **Calculate Your Score**: Count correct answers and calculate percentage
3. **Review Explanations**: Read detailed explanations for ALL questions, including ones you got right
4. **Identify Weak Areas**: Note which domains have the most incorrect answers
5. **Study and Retry**: Focus on weak areas, then retake the exam after studying

### Scoring Guide

- **75%+ (45-60 correct)**: PASS - Ready for the exam
- **60-74% (36-44 correct)**: Close - Review weak areas and retry
- **45-59% (27-35 correct)**: Needs Work - Study fundamentals, then retry
- **Below 45% (0-26 correct)**: More Preparation Needed - Complete all domain study guides first

## Study Recommendations by Score Range

### If you score 75%+ (PASS)
- Take another mock exam to confirm consistency
- Review explanations for questions you got wrong
- Focus on time management (aim to finish in 60-70 minutes)
- Read through exam tips and common traps
- Schedule your actual KCSA exam

### If you score 60-74% (Close)
- Identify your weakest domains from the answer key
- Study those specific domain guides thoroughly
- Complete hands-on labs for weak areas
- Retake the same exam after 2-3 days of focused study
- Take a different mock exam to confirm improvement

### If you score 45-59% (Needs Work)
- Review all domain study guides systematically
- Complete all hands-on labs in order
- Focus on understanding concepts, not memorization
- Use the KCSA cheatsheet for quick reference
- Retake exam after 1 week of comprehensive study

### If you score below 45% (More Preparation Needed)
- Start from Domain 1 and work through all materials
- Set up a local Kubernetes cluster for practice
- Complete all labs with detailed notes
- Don't rush - understanding is more important than speed
- Retake exam after 2-3 weeks of thorough preparation

## Key Topics to Master

Based on exam frequency and importance:

### High Priority (Appear Most Frequently)
- NetworkPolicy creation and troubleshooting
- RBAC (Roles, RoleBindings, ClusterRoles, ClusterRoleBindings)
- Security Context (runAsNonRoot, capabilities, readOnlyRootFilesystem)
- Pod Security Admission (enforce/audit/warn modes)
- Secret management and encryption at rest
- Image scanning with Trivy
- Admission controllers configuration
- Falco rule syntax and detection
- Audit logging and policy configuration

### Medium Priority (Regular Appearance)
- Service account security and token management
- AppArmor and Seccomp profile application
- CIS Benchmark tool (kube-bench)
- Ingress TLS configuration
- Image signing with Cosign
- Registry security (Harbor, private registries)
- Runtime security monitoring
- SBOM generation and analysis
- Supply chain attack vectors

### Lower Priority (Occasional)
- Kernel security hardening
- Container runtime internals
- SELinux policies
- Advanced OPA/Gatekeeper policies
- Certificate management
- Custom admission webhooks

## Question Format Examples

### Scenario-Based Question
```
You are securing a multi-tenant Kubernetes cluster. A development team needs to deploy
applications in the 'dev' namespace but should not be able to access production secrets
or modify cluster-wide resources. What is the MOST appropriate RBAC configuration?

A. Create a ClusterRole with full permissions and bind it to the dev team
B. Create a Role in the dev namespace with necessary permissions and create a RoleBinding
C. Create a ClusterRole and bind it cluster-wide with ClusterRoleBinding
D. Grant cluster-admin role to the dev team with namespace restrictions

Correct Answer: B
```

### Troubleshooting Question
```
A pod fails to start with the error "container has runAsNonRoot and image will run as root".
What is the MOST appropriate solution?

A. Set automountServiceAccountToken to false
B. Add the runAsUser field in securityContext with a non-zero value
C. Remove the readOnlyRootFilesystem restriction
D. Add the SYS_ADMIN capability to the container

Correct Answer: B
```

## Common Exam Traps to Avoid

1. **Confusing namespace vs cluster scope**: Know when to use Role vs ClusterRole
2. **Missing security context hierarchy**: Container settings override pod settings
3. **NetworkPolicy default behavior**: All traffic is ALLOWED by default (not denied)
4. **Secret encoding vs encryption**: base64 encoding is NOT encryption
5. **ServiceAccount auto-mounting**: Tokens are mounted by default (disable when not needed)
6. **Pod Security Admission modes**: Understand difference between enforce, audit, and warn
7. **RBAC is additive**: Multiple roles combine permissions (no deny rules)
8. **Image tags are mutable**: Use digests for immutability, not tags like 'latest'
9. **Admission controller order**: Mutating runs before validating
10. **Capabilities are lowercase**: Use 'NET_ADMIN' not 'net_admin' in manifest

## Tips for Exam Success

### Before the Exam
- Take all three mock exams under timed conditions
- Review the KCSA Cheatsheet thoroughly
- Complete all hands-on labs at least once
- Get comfortable with kubectl commands
- Understand the "why" behind each security control

### During the Exam
- Read each question carefully - watch for keywords like "MOST", "LEAST", "NOT"
- Eliminate obviously wrong answers first
- Watch your time - aim for 1.5 minutes per question
- Flag difficult questions and return to them later
- Don't overthink - your first instinct is usually correct

### After the Exam
- Learn from mistakes - wrong answers are learning opportunities
- Review explanations even for correct answers
- Focus on understanding concepts, not memorizing answers
- Practice weak areas with hands-on labs
- Retake exams to track improvement

## Additional Resources

- **Study Guides**: [domains/](../domains/) - Comprehensive guides for all six domains
- **Hands-On Labs**: [labs/](../labs/) - Practical exercises for each domain
- **Cheatsheet**: [KCSA_CHEATSHEET.md](../KCSA_CHEATSHEET.md) - Quick reference for exam day
- **Official Docs**: [kubernetes.io/docs](https://kubernetes.io/docs/) - Official Kubernetes documentation

## Exam Day Preparation Checklist

- [ ] Scored 75%+ on all three mock exams consistently
- [ ] Can complete common tasks without documentation:
  - [ ] Create NetworkPolicy with ingress/egress rules
  - [ ] Configure RBAC with Roles and RoleBindings
  - [ ] Apply Security Context to pods/containers
  - [ ] Set up Pod Security Admission for a namespace
  - [ ] Scan images with Trivy and interpret results
  - [ ] Create and apply Falco rules
  - [ ] Configure audit logging policy
  - [ ] Set up admission controllers
- [ ] Understand all domain concepts thoroughly
- [ ] Completed all hands-on labs successfully
- [ ] Can explain WHY security controls are necessary
- [ ] Comfortable with time management (finish in 70-80 minutes)

## Contributing

Found an error or have a suggestion for improvement? Please open an issue or submit a pull request.

## License

This content is part of the KCSA Study Guide and is provided for educational purposes.

---

**Ready to start?** Begin with [Mock Exam Set 1](mock-exam-set-1.md) for your baseline assessment.

**Need to study first?** Return to the [main README](../README.md) to review domain content.
