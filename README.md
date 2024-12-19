# proximity-backend

# promote to staging:
git checkout staging
git merge development
git push origin staging

# promote to production:
git checkout main
git merge staging
git push origin main