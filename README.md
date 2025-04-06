# Personal Device Locator

A secure, privacy-focused personal device tracking application built with Python and Tkinter.

## Features

- 🔒 Secure device tracking with end-to-end encryption
- 📱 Multiple device support (smartphones, tablets, laptops, desktops)
- 🗺️ Real-time location tracking with OpenStreetMap integration
- 🔐 Two-factor authentication support
- 📊 Location history and analytics
- 🛡️ Privacy-focused with user consent management
- 📝 Comprehensive activity logging
- ⚙️ Customizable data retention settings

## Security Features

- End-to-end encryption for location data
- Secure password hashing using PBKDF2
- Session management with secure tokens
- Rate limiting to prevent abuse
- Input validation and sanitization
- Activity monitoring and logging

## Privacy Features

- User consent required for tracking
- Configurable data retention periods
- Data export functionality
- Transparent activity logging
- Location data encryption

## Requirements

- Python 3.8+
- Tkinter
- SQLite3
- Additional requirements in `requirements.txt`

## Installation

1. Clone the repository:
```bash
git clone https://github.com/A5873/personal-device-locator.git
cd personal-device-locator
```

2. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Run the application:
```bash
python CyberTrack.py
```

## Testing

Run the test suite:
```bash
python -m pytest tests/
```

## Development

To contribute to the project:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests
5. Submit a pull request

## License

MIT License - see LICENSE file for details

## Author

[A5873](https://github.com/A5873)
