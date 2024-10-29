import express from "express";
import multer from "multer";
import fs from "fs"; // Import the fs module



const app = express();
const port = 3000;

const upload = multer({ dest: 'uploads/' });
import { BlobServiceClient, AnonymousCredential } from "@azure/storage-blob";
import uniqid from "uniqid";

const AZURE_STORAGE_SAS_URL = "https://linklistsumitkumar.blob.core.windows.net/linklist-files?sp=racwdli&st=2024-10-28T05:19:58Z&se=2024-10-28T16:19:58Z&sv=2022-11-02&sr=c&sig=C01Tu3L2NX4W3WDn9zIDsMef%2B%2BqEEQ8wZeh6KQ03QLE%3D";
const AZURE_BLOB_STORAGE_CONTAINER_NAME = "linklist-files";
const AZURE_STORAGE_ACCOUNT_NAME = "linklistsumitkumar";
const uploadImageToAzure = async (file) => {
    try {
        console.log("Starting image upload...");

        const validImageTypes = ["image/jpeg", "image/png", "image/gif", "image/webp"];
        console.log("File MIME type:", file.mimetype);
        if (!validImageTypes.includes(file.mimetype)) {
            throw new Error("Invalid file type. Please upload an image.");
        }

        console.log("1 - Initializing BlobServiceClient...");
        const blobServiceClient = new BlobServiceClient(AZURE_STORAGE_SAS_URL, new AnonymousCredential());
        const containerClient = blobServiceClient.getContainerClient(AZURE_BLOB_STORAGE_CONTAINER_NAME);
        console.log("2 - Container client initialized.");

        const randomId = uniqid();
        const ext = file.originalname.split('.').pop(); 
        const newFilename = `${randomId}.${ext}`;
        console.log("3 - New filename generated:", newFilename);

        const blockBlobClient = containerClient.getBlockBlobClient(newFilename);

       
        console.log("File path to read:", file.path);

        
        if (!fs.existsSync(file.path)) {
            console.error("File does not exist at the path:", file.path);
            throw new Error(`File does not exist at path: ${file.path}`);
        }

        const arrayBuffer = await fs.promises.readFile(file.path);
        console.log("4 - File read into ArrayBuffer.");

       
        await blockBlobClient.uploadData(arrayBuffer, {
            blobHTTPHeaders: { blobContentType: file.mimetype }
        });

        console.log("Upload successful.");
        return `https://${AZURE_STORAGE_ACCOUNT_NAME}.blob.core.windows.net/${AZURE_BLOB_STORAGE_CONTAINER_NAME}/${newFilename}`;
    } catch (error) {
        console.error("Upload error:", error);
        throw new Error(`Image upload failed: ${error.message}`);
    }
};


app.post('/upload', upload.single('file'), async (req, res) => {
    console.log("Request body: ", req.body);
    const filePath = req.file;
    if (!filePath) {
        return res.status(400).json({ error: 'No file uploaded' });
    }

    console.log("filepath is ",filePath) 

    try {
        const fileUrl = await uploadImageToAzure(filePath);
        console.log("filruri is ",fileUrl)
        res.status(200).json({ message: 'File uploaded successfully', url: fileUrl });
    } catch (error) {
        res.status(500).json({ error: 'Failed to upload file to Azure' });
    }
});

// Start server
const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
});
