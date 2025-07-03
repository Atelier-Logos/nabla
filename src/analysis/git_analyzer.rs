use anyhow::Result;
use chrono::{DateTime, Utc};
use git2::Repository;
use std::path::Path;

pub struct GitAnalysis {
    pub last_commit: Option<DateTime<Utc>>,
    pub publish_date: Option<DateTime<Utc>>,
}

pub async fn analyze(package_path: &Path) -> Result<GitAnalysis> {
    tracing::debug!("Running git analysis on {:?}", package_path);

    let last_commit = get_last_commit_date(package_path).await;
    let publish_date = get_publish_date(package_path).await;

    Ok(GitAnalysis {
        last_commit,
        publish_date,
    })
}

async fn get_last_commit_date(package_path: &Path) -> Option<DateTime<Utc>> {
    // Try to open the git repository
    match Repository::discover(package_path) {
        Ok(repo) => {
            // Get the HEAD commit
            match repo.head() {
                Ok(head) => {
                    match head.target() {
                        Some(oid) => {
                            match repo.find_commit(oid) {
                                Ok(commit) => {
                                    let time = commit.time();
                                    let timestamp = time.seconds();
                                    
                                    match DateTime::from_timestamp(timestamp, 0) {
                                        Some(dt) => Some(dt),
                                        None => {
                                            tracing::warn!("Invalid timestamp from git commit: {}", timestamp);
                                            None
                                        }
                                    }
                                }
                                Err(e) => {
                                    tracing::warn!("Failed to find commit: {}", e);
                                    None
                                }
                            }
                        }
                        None => {
                            tracing::warn!("HEAD has no target");
                            None
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("Failed to get HEAD: {}", e);
                    None
                }
            }
        }
        Err(e) => {
            tracing::debug!("No git repository found at {:?}: {}", package_path, e);
            None
        }
    }
}

async fn get_publish_date(package_path: &Path) -> Option<DateTime<Utc>> {
    // Try to get the first commit (approximates publish date)
    match Repository::discover(package_path) {
        Ok(repo) => {
            // Walk through all commits to find the earliest one
            match repo.head() {
                Ok(head) => {
                    match head.target() {
                        Some(oid) => {
                            match find_first_commit(&repo, oid) {
                                Ok(first_commit) => {
                                    let time = first_commit.time();
                                    let timestamp = time.seconds();
                                    
                                    match DateTime::from_timestamp(timestamp, 0) {
                                        Some(dt) => Some(dt),
                                        None => {
                                            tracing::warn!("Invalid timestamp from first commit: {}", timestamp);
                                            None
                                        }
                                    }
                                }
                                Err(e) => {
                                    tracing::warn!("Failed to find first commit: {}", e);
                                    None
                                }
                            }
                        }
                        None => None
                    }
                }
                Err(_) => None
            }
        }
        Err(_) => None
    }
}

fn find_first_commit(repo: &Repository, start_oid: git2::Oid) -> Result<git2::Commit, git2::Error> {
    let mut revwalk = repo.revwalk()?;
    revwalk.push(start_oid)?;
    revwalk.set_sorting(git2::Sort::TIME | git2::Sort::REVERSE)?;
    
    // Get the first commit (oldest)
    if let Some(oid) = revwalk.next() {
        let oid = oid?;
        repo.find_commit(oid)
    } else {
        // If no commits found, return the starting commit
        repo.find_commit(start_oid)
    }
} 