# SHA_256_encryption
SHA-256 Implementation in xv6 (RISC-V)
Project Overview:
This project demonstrates the implementation and analysis of the SHA-256 cryptographic hash function within the minimalist xv6 operating system (targeting the RISC-V architecture). Three different approaches are explored:

Kernel Space Implementation

User Space Implementation

System Call-Based Implementation

Each approach is evaluated based on performance, security implications, and development complexity, providing valuable insights into the trade-offs of system-level cryptographic operations.

Project Motivation:
Efficient and secure cryptographic operations are vital for system-level software. The project aims to: • Optimize performance by integrating SHA-256 in kernel space. • Enhance security by isolating cryptographic operations. • Provide usability via a system call interface that bridges kernel and user spaces.

Implementation Details:
Kernel Space Implementation

Description: Implements the SHA-256 algorithm directly within the xv6 kernel, leveraging low-level hardware capabilities.

Key Features: • A dedicated module (sha256kernel.c) with cryptographic functions. • Integration into the kernel’s boot process to verify functionality. • Modifications to system call tables to enable later interaction.

User Space Implementation

Description: A standalone user-space program (sha256test.c) computes SHA-256 using standard C libraries.

Key Features: • Handles input/output operations for hashing. • Easier debugging and safer error isolation. • Tested with various input strings to ensure correct hash outputs.

System Call-Based Implementation

Description: Creates a custom system call (sha256encrypt) to allow user applications to access the kernel’s SHA-256 functionality.

Key Features: • Kernel modifications (in syscall.c and syscall.h) to implement the system call. • A user-space wrapper (sha256sys.c) to facilitate system call invocation. • Balances performance with a secure and accessible interface.

Development Environment:
• Operating System: xv6 (RISC-V) • Emulation: QEMU • Tools: GCC, GDB, Make • Editor: Any preferred text editor or IDE

The development and testing were conducted on a Linux system with QEMU emulating the RISC-V architecture.

Testing & Benchmarking:
The project underwent extensive testing, including:

• Functional Testing:

Predefined inputs such as “hello”, “world”, and empty strings to verify correct outputs.

Boundary testing with extremely short and long input strings.

• Performance Benchmarking:

Measurement of execution times using system timers (e.g., uptime() in the kernel).

Analysis of resource utilization across various input sizes (from 1 KB to 10 MB).

• Security Testing:

Evaluation of potential vulnerabilities in memory management and buffer handling.

Examination of the system call interface for secure data exchange.

Performance and Security Analysis:
• Kernel Space:

Performance: Maximum speed due to direct hardware interaction.

Security: Higher risk if vulnerabilities are present; more challenging debugging.

• User Space:

Performance: Slight overhead due to user-kernel transitions.

Security: Safer as issues remain isolated within the application.

• System Call Interface:

Performance: Provides a balanced approach, maintaining good performance.

Security: Offers controlled access to kernel functionality with proper boundary checks.

Challenges and Future Work:
Challenges encountered during the project include: • Memory Management: Efficient allocation and deallocation in kernel space. • Data Exchange: Managing buffer sizes for transferring data between user and kernel spaces. • Testing Complexity: Debugging kernel code is inherently more complex than debugging user-space applications.

Future work will focus on: • Expanding input handling to support file inputs. • Implementing more granular performance analyses, such as latency testing. • Further optimizing memory management and buffer handling to enhance overall stability and security.
