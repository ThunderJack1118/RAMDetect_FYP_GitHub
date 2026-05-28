# Run from RAMDetect project root after copying the deployment patch files.
# Replace <YOUR_USERNAME> and repository URL.

git init
git branch -M main

# Optional, but recommended if model files become large:
# git lfs install
# git lfs track "*.pkl" "*.keras" "*.h5" "*.joblib"
# git add .gitattributes

git add .
git commit -m "Initial RAMDetect private FYP deployment source"

git remote add origin https://github.com/<YOUR_USERNAME>/RAMDetect.git
git push -u origin main
