# Development Workflow

This project addresses the issue of unstable versions by separating **stable production code** from **active development**.

## Branching Strategy

We use a simplified Gitflow strategy:

| Branch | Purpose | Stability |
| :--- | :--- | :--- |
| `main` | Production-ready code. Only receives merges from `develop` (for releases) or hotfixes. | **Stable** |
| `develop` | Integration branch for features. | **Unstable/Testing** |
| `feat/xyz` | Temporary feature branches. | **Experimental** |

## Workflows

### 1. Starting a New Feature
When you want to work on a new feature or fix:

```bash
# Make sure you are on develop and up to date
git checkout develop
# git pull # if remote exists

# Create a new branch
git checkout -b feat/your-feature-name
```

### 2. Development
Work on your feature, commit changes often.
```bash
git add .
git commit -m "feat: added new login screen"
```

### 3. Merging Feature
Once the feature is working and tested:

```bash
# Switch to develop
git checkout develop

# Merge your feature
git merge feat/your-feature-name

# Delete the feature branch
git branch -d feat/your-feature-name
```

### 4. Creating a Release
When `develop` is stable and ready for release:

```bash
git checkout main
git merge develop
git tag -a v1.0.1 -m "Version 1.0.1"
```
