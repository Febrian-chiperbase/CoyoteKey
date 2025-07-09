# Contributing to CoyoteKey

Thank you for your interest in contributing to CoyoteKey! This document provides guidelines for contributing to this enterprise API security testing platform.

## 🚀 Getting Started

### Prerequisites
- Go 1.19 or higher
- Git
- Basic understanding of API security testing
- Familiarity with web technologies (HTML/CSS/JavaScript) for GUI contributions

### Development Setup
```bash
# Clone the repository
git clone https://github.com/Febrian-chiperbase/CoyoteKey.git
cd CoyoteKey

# Install dependencies
go mod tidy

# Build the project
make build

# Run tests
make test

# Run demos
make demo
```

## 🎯 How to Contribute

### 1. Reporting Issues
- Use GitHub Issues to report bugs or request features
- Provide detailed information including:
  - Operating system and version
  - Go version
  - Steps to reproduce
  - Expected vs actual behavior
  - Screenshots for GUI issues

### 2. Feature Requests
- Check existing issues first
- Clearly describe the feature and its use case
- Explain how it fits with CoyoteKey's goals
- Consider implementation complexity

### 3. Code Contributions

#### Pull Request Process
1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Make your changes
4. Add tests for new functionality
5. Update documentation
6. Commit with descriptive messages
7. Push to your fork
8. Create a Pull Request

#### Coding Standards
- Follow Go best practices and conventions
- Use meaningful variable and function names
- Add comments for complex logic
- Maintain consistent code formatting
- Write unit tests for new features

#### Commit Message Format
```
🎯 Type: Brief description

Detailed explanation of changes made.

- Feature 1
- Feature 2
- Bug fix 3
```

Types:
- 🚀 `feat`: New feature
- 🐛 `fix`: Bug fix
- 📚 `docs`: Documentation
- 🎨 `style`: Code style/formatting
- ♻️ `refactor`: Code refactoring
- ✅ `test`: Adding tests
- 🔧 `chore`: Maintenance tasks

## 🛠️ Development Areas

### Core Engine
- API key brute force algorithms
- Multi-target support
- Rate limiting and throttling
- Error handling and retry logic

### Machine Learning
- Pattern recognition improvements
- Success prediction algorithms
- Adaptive learning mechanisms
- Model training optimization

### Database Integration
- New database drivers
- Query optimization
- Analytics improvements
- Data visualization

### Web Dashboard
- UI/UX improvements
- New chart types
- Real-time features
- Mobile responsiveness

### Security Features
- WAF detection methods
- Evasion techniques
- Authentication methods
- Stealth capabilities

### API Discovery
- New endpoint detection methods
- Schema analysis improvements
- Version detection
- Documentation parsing

## 🧪 Testing

### Running Tests
```bash
# Run all tests
make test

# Run specific test
go test ./pkg/brutekey -v

# Run with coverage
go test -cover ./...
```

### Test Categories
- Unit tests for individual functions
- Integration tests for component interaction
- End-to-end tests for complete workflows
- Performance tests for optimization

### Adding Tests
- Write tests for all new functionality
- Maintain test coverage above 80%
- Use table-driven tests where appropriate
- Mock external dependencies

## 📚 Documentation

### Code Documentation
- Add GoDoc comments for public functions
- Include usage examples
- Document complex algorithms
- Explain security considerations

### User Documentation
- Update README.md for new features
- Add examples to demo scripts
- Update command-line help text
- Create tutorial content

### API Documentation
- Document new API endpoints
- Include request/response examples
- Explain authentication requirements
- Add error code descriptions

## 🔒 Security Considerations

### Responsible Disclosure
- Report security vulnerabilities privately
- Allow time for fixes before public disclosure
- Provide detailed reproduction steps
- Suggest mitigation strategies

### Code Security
- Validate all user inputs
- Sanitize output data
- Use secure coding practices
- Avoid hardcoded credentials
- Implement proper error handling

## 🎨 GUI Contributions

### Web Dashboard
- Follow modern web standards
- Ensure mobile responsiveness
- Maintain accessibility compliance
- Use consistent design patterns

### Technologies
- HTML5 semantic markup
- CSS3 with modern features
- Vanilla JavaScript (ES6+)
- Chart.js for visualizations
- WebSocket for real-time updates

### Design Guidelines
- Follow existing color scheme
- Maintain consistent spacing
- Use appropriate icons and typography
- Ensure cross-browser compatibility

## 📋 Code Review Process

### Review Criteria
- Code quality and style
- Test coverage
- Documentation completeness
- Security implications
- Performance impact
- Backward compatibility

### Review Timeline
- Initial review within 48 hours
- Follow-up reviews within 24 hours
- Merge after approval from maintainers

## 🏷️ Release Process

### Version Numbering
- Follow Semantic Versioning (SemVer)
- Major.Minor.Patch format
- Tag releases with descriptive messages

### Release Types
- **Major**: Breaking changes, new architecture
- **Minor**: New features, backward compatible
- **Patch**: Bug fixes, small improvements

## 🤝 Community Guidelines

### Code of Conduct
- Be respectful and inclusive
- Welcome newcomers
- Provide constructive feedback
- Focus on technical merit
- Maintain professional communication

### Communication Channels
- GitHub Issues for bug reports and features
- GitHub Discussions for general questions
- Pull Requests for code contributions
- Email for security issues

## 🎯 Contribution Ideas

### Beginner-Friendly
- Fix typos in documentation
- Add new wordlist examples
- Improve error messages
- Add unit tests

### Intermediate
- Implement new authentication methods
- Add database drivers
- Create new demo scripts
- Improve GUI components

### Advanced
- Machine learning algorithms
- Advanced evasion techniques
- Performance optimizations
- Security enhancements

## 📞 Getting Help

### Resources
- README.md for basic usage
- CHANGELOG.md for version history
- Demo scripts for examples
- Code comments for implementation details

### Support
- GitHub Issues for technical questions
- GitHub Discussions for general help
- Code review feedback for improvements

## 🙏 Recognition

Contributors will be recognized in:
- CHANGELOG.md for their contributions
- README.md contributors section
- Release notes for significant features
- GitHub contributor statistics

Thank you for helping make CoyoteKey better! 🚀
