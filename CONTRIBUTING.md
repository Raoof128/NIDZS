# Contributing to Network IDS

First off, thank you for considering contributing to this Network Intrusion Detection System! This is primarily a portfolio project, but community contributions are welcome and appreciated.

---

## 📋 Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How Can I Contribute?](#how-can-i-contribute)
- [Development Setup](#development-setup)
- [Contribution Guidelines](#contribution-guidelines)
- [Style Guides](#style-guides)
- [Commit Message Convention](#commit-message-convention)
- [Pull Request Process](#pull-request-process)
- [Community](#community)

---

## 📜 Code of Conduct

This project adheres to a standard Code of Conduct. By participating, you are expected to uphold this code.

**Our Standards:**
- Be respectful and inclusive
- Welcome newcomers and help them learn
- Accept constructive criticism gracefully
- Focus on what is best for the community
- Show empathy towards other community members

**Unacceptable Behavior:**
- Harassment, trolling, or discriminatory language
- Publishing others' private information
- Spam or off-topic discussions
- Any conduct considered inappropriate in a professional setting

---

## 🤝 How Can I Contribute?

### Reporting Bugs

Before creating bug reports, please check existing issues to avoid duplicates.

**Good Bug Reports Include:**
- Clear, descriptive title
- Exact steps to reproduce the problem
- Expected vs actual behavior
- Screenshots if applicable
- Environment details (OS, Docker version, etc.)
- Relevant log output

**Bug Report Template:**
```markdown
**Describe the bug**
A clear description of what the bug is.

**To Reproduce**
Steps to reproduce:
1. Deploy with `./scripts/deploy.sh`
2. Run command '....'
3. See error

**Expected behavior**
What you expected to happen.

**Environment**
- OS: [e.g., Ubuntu 22.04]
- Docker version: [e.g., 24.0.7]
- Docker Compose version: [e.g., 2.23.0]

**Logs**
```
Paste relevant logs here
```

**Additional context**
Any other relevant information.
```

### Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues.

**Good Enhancement Suggestions Include:**
- Use case or problem the enhancement solves
- Current behavior vs proposed behavior
- Why this enhancement would be useful
- Possible implementation approach (if known)

### Contributing Code

We love code contributions! Here are areas where help is especially valuable:

**High Priority:**
- 🔴 Bug fixes
- 🟡 Detection rule improvements (reducing false positives)
- 🟡 Performance optimizations
- 🟢 Documentation improvements
- 🟢 Test coverage expansion

**Feature Requests:**
- Additional Zeek detection scripts
- More Suricata rules for emerging threats
- Enhanced Kibana dashboards
- Integration with threat intelligence feeds
- Automated reporting capabilities

---

## 💻 Development Setup

### Prerequisites

- Docker 24.0+
- Docker Compose 2.20+
- Git
- Text editor (VS Code, Vim, etc.)
- 8GB RAM minimum, 16GB recommended

### Getting Started

**1. Fork and Clone**
```bash
# Fork the repository on GitHub, then:
git clone https://github.com/YOUR_USERNAME/NIDZS.git
cd NIDZS

# Add upstream remote
git remote add upstream https://github.com/Raoof128/NIDZS.git
```

**2. Create Feature Branch**
```bash
git checkout -b feature/your-feature-name
```

**3. Deploy Development Environment**
```bash
./scripts/deploy.sh
```

**4. Make Changes**
- Edit files
- Test thoroughly
- Document changes

**5. Validate Changes**
```bash
# Run tests
./scripts/test-detection.sh

# Verify deployment
./scripts/verify-deployment.sh

# Check Zeek script syntax
docker-compose exec zeek zeek -C zeek-scripts/your-script.zeek

# Check Suricata rules
docker-compose exec suricata suricata -T -c /etc/suricata/suricata.yaml
```

**6. Commit and Push**
```bash
git add .
git commit -m "feat: Add new DNS exfiltration detection"
git push origin feature/your-feature-name
```

**7. Create Pull Request**
- Go to your fork on GitHub
- Click "New Pull Request"
- Fill out the PR template (see below)

---

## 📝 Contribution Guidelines

### Zeek Scripts

**When contributing Zeek scripts:**

1. **Follow Zeek Coding Standards**
   ```zeek
   module YourModule;

   export {
       # Clear documentation
       redef enum Notice::Type += {
           Your_Detection_Notice,
       };
   }

   # Well-commented functions
   function detect_threat(c: connection) {
       # Implementation
   }
   ```

2. **Include Documentation**
   - Purpose and detection logic
   - MITRE ATT&CK mapping
   - False positive considerations
   - Tuning recommendations

3. **Test Thoroughly**
   - Test with sample traffic
   - Document expected alerts
   - Check for false positives

4. **Performance Considerations**
   - Avoid expensive operations in hot paths
   - Use SumStats for aggregations
   - Consider memory usage

### Suricata Rules

**When contributing Suricata rules:**

1. **Follow Rule Conventions**
   ```
   alert tcp $HOME_NET any -> $EXTERNAL_NET any (
       msg:"THREAT_NAME Description";
       flow:established,to_server;
       content:"signature";
       fast_pattern;
       classtype:trojan-activity;
       sid:27XXXXX;
       rev:1;
       metadata:created_at 2024_11_15, updated_at 2024_11_15;
   )
   ```

2. **SID Ranges** (custom rules):
   - 2700000-2799999: Custom rules
   - Avoid conflicts with existing rules

3. **Performance**
   - Use `fast_pattern` for optimal performance
   - Avoid regex when possible
   - Test rule performance impact

4. **Documentation**
   - Describe what the rule detects
   - Include sample traffic that triggers it
   - Document false positive scenarios

### Documentation

**When contributing documentation:**

1. **Use Clear, Concise Language**
2. **Include Examples**
3. **Keep Formatting Consistent**
4. **Test All Commands/Code Snippets**
5. **Update Table of Contents**

### Scripts

**When contributing scripts:**

1. **Use Bash Best Practices**
   ```bash
   #!/bin/bash
   set -euo pipefail  # Exit on error, undefined vars, pipe failures

   # Colors
   RED='\033[0;31m'
   GREEN='\033[0;32m'
   NC='\033[0m'

   # Functions with clear names
   check_prerequisites() {
       # Implementation
   }
   ```

2. **Include Help/Usage**
   ```bash
   usage() {
       echo "Usage: $0 [OPTIONS]"
       echo "Options:"
       echo "  --help    Show this message"
       exit 0
   }
   ```

3. **Error Handling**
   - Check for required commands
   - Provide helpful error messages
   - Clean up on failure

4. **Make Scripts Executable**
   ```bash
   chmod +x scripts/your-script.sh
   ```

---

## 🎨 Style Guides

### Zeek Code Style

- **Indentation:** 4 spaces (no tabs)
- **Naming:** snake_case for variables/functions
- **Comments:** Explain "why", not "what"
- **Module Organization:** Group related functionality

### Shell Script Style

- **Indentation:** 4 spaces
- **Quoting:** Always quote variables: `"$var"`
- **Functions:** Use lowercase with underscores
- **Comments:** Document complex logic

### Documentation Style

- **Markdown:** Use GitHub Flavored Markdown
- **Headings:** Use ATX-style (# Heading)
- **Code Blocks:** Always specify language
- **Links:** Use descriptive link text

---

## 📌 Commit Message Convention

We follow the [Conventional Commits](https://www.conventionalcommits.org/) specification.

**Format:**
```
<type>(<scope>): <subject>

<body>

<footer>
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code refactoring
- `perf`: Performance improvements
- `test`: Adding/updating tests
- `chore`: Build process, tooling, etc.

**Examples:**
```bash
# Feature
git commit -m "feat(zeek): Add SMB file transfer detection script"

# Bug fix
git commit -m "fix(suricata): Correct false positive in DNS tunneling rule"

# Documentation
git commit -m "docs(readme): Add troubleshooting section for Elasticsearch"

# Performance
git commit -m "perf(zeek): Optimize C2 beaconing detection algorithm"
```

**Multi-line commit:**
```bash
git commit -m "feat(dashboards): Add threat intelligence dashboard

- Integrated MISP feed visualization
- Added IOC timeline view
- Included attribution analysis panel

Closes #42"
```

---

## 🔄 Pull Request Process

### Before Submitting

- [ ] Code follows project style guides
- [ ] All tests pass (`./scripts/test-detection.sh`)
- [ ] Documentation updated (if needed)
- [ ] Commit messages follow convention
- [ ] No merge conflicts with main branch

### PR Template

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Documentation update
- [ ] Performance improvement

## Testing
How has this been tested?

## Checklist
- [ ] My code follows the project style guidelines
- [ ] I have commented my code where necessary
- [ ] I have updated documentation
- [ ] My changes generate no new warnings
- [ ] I have added tests
- [ ] All tests pass

## Screenshots (if applicable)

## Additional Notes
```

### Review Process

1. **Automated Checks** (if configured)
   - Linting passes
   - Tests pass

2. **Code Review**
   - At least one maintainer review required
   - Address all feedback
   - Update PR as needed

3. **Merge**
   - Squash and merge for clean history
   - Delete feature branch after merge

---

## 🌟 Recognition

Contributors will be recognized in:
- README.md Contributors section
- Release notes (for significant contributions)
- Project documentation (for major features)

---

## ❓ Questions?

**Have questions about contributing?**

- 📧 Open an issue with the `question` label
- 💬 Comment on relevant issues/PRs
- 📖 Review existing documentation

---

## 📚 Additional Resources

- [Zeek Scripting Documentation](https://docs.zeek.org/en/master/scripting/index.html)
- [Suricata Rule Writing Guide](https://suricata.readthedocs.io/en/latest/rules/index.html)
- [GitHub Flow Guide](https://guides.github.com/introduction/flow/)
- [Conventional Commits](https://www.conventionalcommits.org/)

---

**Thank you for contributing! 🎉**

Your contributions help make this project better for everyone in the cybersecurity community.

---

**Last Updated:** 2024-11-15
**Version:** 1.2.0
