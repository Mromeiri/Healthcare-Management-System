# Healthcare Management System

A comprehensive electronic health record (EHR) system built with Python and Tkinter that facilitates management of patient records across different healthcare roles.

## Overview

The Healthcare Management System is designed to streamline the workflow of healthcare professionals and improve patient care through efficient record management. The system supports multiple user roles including physicians, radiologists, lab technicians, and patients, with each role having specific access permissions and functionalities.

## Features

- **Multi-role Access System**:
  - Physicians can create medical records, add medical notes, and access comprehensive patient information
  - Radiologists can add and view imaging results
  - Lab technicians can add and view laboratory test results
  - Patients can view their own medical records, notes, imaging, and lab results

- **User-friendly Interface**:
  - Modern, intuitive GUI built with Tkinter
  - Role-specific dashboards and functionality
  - Searchable patient records and medical files

- **Security Features**:
  - Role-based access control
  - Secure authentication system
  - Data privacy protections

- **Record Management**:
  - Create and manage patient medical records
  - Add medical notes, imaging results, and lab results
  - View comprehensive patient history
  - Search and filter functionality

## Technical Details

- **Backend**: Python with SQLite database
- **Frontend**: Tkinter with custom styling
- **Architecture**: Object-oriented design with MVC pattern

## Screenshots

*(Add screenshots of the application here)*

## Installation

1. Clone the repository:
   ```
   git clone https://github.com/Mromeiri/Healthcare-Management-System.git
   ```

2. Navigate to the project directory:
   ```
   cd Healthcare-Management-System
   ```

3. Install required dependencies:
   ```
   pip install -r requirements.txt
   ```

4. Run the application:
   ```
   python main.py
   ```

## Usage

### Login

- Launch the application and login using your credentials
- Select your role (physician, radiologist, lab technician, or patient)

### For Physicians

- Create new patient records by entering patient ID
- Add medical notes to existing records
- View patients' medical history, imaging results, and lab tests
- Search for specific patient records

### For Radiologists

- View assigned imaging requests
- Add imaging results to patient records
- Access relevant patient information

### For Lab Technicians

- View assigned lab test requests
- Add laboratory results to patient records
- Access relevant patient information

### For Patients

- View personal medical records
- Access medical notes, imaging results, and lab test results

## System Architecture

The application follows a modular design with the following key components:

- **ManagementFrame**: Main interface that adapts based on user role
- **Authentication System**: Handles user login and role validation
- **Database Connection**: Manages data storage and retrieval
- **Role-specific Logic**: Implements functionality for each healthcare role

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Healthcare professionals who provided domain expertise
- Contributors and testers who helped improve the system

## Contact

Project Link: [https://github.com/Mromeiri/Healthcare-Management-System](https://github.com/Mromeiri/Healthcare-Management-System)
