// NIDS JavaScript functionality
document.addEventListener('DOMContentLoaded', function() {
    // File upload drag and drop functionality
    const uploadArea = document.querySelector('.upload-area');
    const fileInput = document.getElementById('pcapFile');
    
    // Validation constants
    const MAX_FILE_SIZE = 500 * 1024 * 1024; // 500MB in bytes
    const ALLOWED_EXTENSIONS = ['.pcap', '.pcapng'];
    
    function showValidationModal(message) {
        const modalEl = document.getElementById('validationModal');
        const msgEl = document.getElementById('validationMessage');
        
        if (modalEl && msgEl) {
            msgEl.textContent = message;
            // Use bootstrap global object if available, assuming it's loaded in the page
            const modal = new bootstrap.Modal(modalEl);
            modal.show();
        } else {
            // Fallback if modal elements are missing
            alert(message);
        }
    }

    function validateFiles(files) {
        let valid = true;
        let errorMessage = "";

        for (let i = 0; i < files.length; i++) {
            const file = files[i];
            
            // Check file extension
            const fileName = file.name.toLowerCase();
            const isValidExtension = ALLOWED_EXTENSIONS.some(ext => fileName.endsWith(ext));
            
            if (!isValidExtension) {
                errorMessage = `File "${file.name}" tidak sesuai ekstensinya`;
                valid = false;
                break;
            }
            
            // Check file size
            if (file.size > MAX_FILE_SIZE) {
                errorMessage = `Warning: File "${file.name}" melebihi 500 MB dan tidak bisa dilanjutkan untuk analyze`;
                valid = false;
                break;
            }
        }
        
        if (!valid) {
            showValidationModal(errorMessage);
            return false;
        }
        
        return true;
    }
    
    if (uploadArea && fileInput) {
        uploadArea.addEventListener('click', () => fileInput.click());
        
        uploadArea.addEventListener('dragover', (e) => {
            e.preventDefault();
            uploadArea.classList.add('dragover');
        });
        
        uploadArea.addEventListener('dragleave', () => {
            uploadArea.classList.remove('dragover');
        });
        
        uploadArea.addEventListener('drop', (e) => {
            e.preventDefault();
            uploadArea.classList.remove('dragover');
            
            const files = e.dataTransfer.files;
            if (files.length > 0) {
                if (validateFiles(files)) {
                    fileInput.files = files;
                    // Update text to show number of files
                    const fileText = files.length === 1 ? files[0].name : `${files.length} files selected`;
                    // You might want to update some UI element here to show selected files
                } else {
                    fileInput.value = ''; // Clear the input if invalid
                }
            }
        });
        
        // Add change listener for manual selection
        fileInput.addEventListener('change', function() {
            if (this.files.length > 0) {
                if (!validateFiles(this.files)) {
                    this.value = ''; // Clear the input if invalid
                }
            }
        });
    }
});
