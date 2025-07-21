# Contributing to Auto-Remediation Guidance

Thank you for your interest in contributing to the Nexthink v6 Auto-Remediation Guidance repository! This template is designed to help teams implement auto-remediation with PowerShell 5.1.

---

## 🤝 How to Contribute

### Reporting Issues
- Use the [GitHub Issues](../../issues) page to report bugs or suggest improvements
- Provide clear descriptions and examples when possible
- Include PowerShell version, Nexthink version, and OS details for technical issues

### Suggesting Enhancements
- Check existing issues to avoid duplicates
- Clearly describe the enhancement and its benefits
- Consider providing examples or mockups

### Contributing Code
1. **Fork the repository**
2. **Create a feature branch** from `main`
3. **Make your changes** following our guidelines below
4. **Test your changes** (especially PowerShell scripts)
5. **Submit a pull request** with a clear description

---

## 📝 Content Guidelines

### Documentation
- Use clear, concise language
- Include practical examples
- Follow existing markdown formatting
- Update table of contents when adding new sections

### PowerShell Scripts
- **Target PowerShell 5.1** compatibility
- Include comprehensive error handling
- Use consistent logging format
- Add parameter validation
- Include help documentation with examples

### Playbooks
- Follow the established template structure
- Include troubleshooting sections
- Provide success metrics and KPIs
- Update related resources links

---

## 🔍 Code Review Process

### Pull Request Requirements
- [ ] Clear description of changes
- [ ] PowerShell scripts tested locally
- [ ] Documentation updated if needed
- [ ] No sensitive information included
- [ ] Following existing code style

### Review Criteria
- **Functionality**: Does it work as intended?
- **Compatibility**: Works with PowerShell 5.1?
- **Security**: No hardcoded credentials or sensitive data?
- **Maintainability**: Clear, well-documented code?
- **Consistency**: Follows repository patterns?

---

## 📋 Style Guidelines

### Markdown
- Use consistent heading levels
- Include horizontal rules (`---`) for section breaks
- Use code blocks with appropriate syntax highlighting
- Add emoji icons for visual clarity (sparingly)

### PowerShell
```powershell
# Use verb-noun naming convention
function Start-ServiceRemediation {
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$ServiceName
    )
    
    try {
        # Clear, descriptive comments
        Write-Output "Starting service: $ServiceName"
        # Implementation here
    }
    catch {
        Write-Output "ERROR: $($_.Exception.Message)"
        exit 1
    }
}
```

---

## 🧪 Testing Guidelines

### PowerShell Scripts
- Test on clean Windows 10/11 virtual machines
- Verify with PowerShell 5.1 specifically
- Test error conditions and edge cases
- Validate exit codes and output formats

### Documentation
- Check all links work correctly
- Verify code examples are accurate
- Ensure playbook steps can be followed successfully

---

## 📚 Resources

- [PowerShell Best Practices](https://docs.microsoft.com/en-us/powershell/scripting/developer/cmdlet/strongly-encouraged-development-guidelines)
- [Nexthink v6 Documentation](https://docs.nexthink.com/)
- [GitHub Markdown Guide](https://guides.github.com/features/mastering-markdown/)

---

## 🎉 Recognition

Contributors will be acknowledged in:
- Repository contributors list
- Release notes for significant contributions
- Community recognition for outstanding contributions

---

## 📞 Getting Help

If you need help with contributions:
- Check existing [issues](../../issues) and [discussions](../../discussions)
- Create a new issue with the "question" label
- Reach out to maintainers via GitHub

---

## 📄 License

By contributing to this repository, you agree that your contributions will be licensed under the same [MIT License](LICENSE) that covers the project.

Thank you for helping make auto-remediation more accessible and effective! 🚀