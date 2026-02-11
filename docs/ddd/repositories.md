# FerroCrate Repository Interfaces

> Repository pattern implementations for persisting and retrieving aggregates. Interfaces defined as Rust traits.

## Design Philosophy

Repositories in FerroCrate follow these principles:

1. **One Repository Per Aggregate**: Each aggregate root has a dedicated repository
2. **Trait-Based Abstraction**: Repository interfaces are traits, allowing multiple implementations
3. **Async by Default**: All operations are async for I/O operations
4. **Owned Returns**: `get` methods return owned aggregate instances
5. **Result Types**: All operations return `Result` with domain-specific errors

---

## Repository Trait Pattern

```rust
/// Base trait for all repositories.
#[async_trait]
pub trait Repository<T: Aggregate>: Send + Sync {
    /// Error type for this repository.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Find aggregate by ID.
    async fn find(&self, id: &T::Id) -> Result<Option<T>, Self::Error>;

    /// Save aggregate (insert or update).
    async fn save(&self, aggregate: &T) -> Result<(), Self::Error>;

    /// Delete aggregate by ID.
    async fn delete(&self, id: &T::Id) -> Result<(), Self::Error>;

    /// Check if aggregate exists.
    async fn exists(&self, id: &T::Id) -> Result<bool, Self::Error> {
        Ok(self.find(id).await?.is_some())
    }
}

/// Marker trait for aggregate roots.
pub trait Aggregate: Send + Sync + 'static {
    type Id: Clone + Eq + std::hash::Hash + Display;
    fn id(&self) -> &Self::Id;
}
```

---

## Container Repository

```rust
/// Repository for Container aggregates.
#[async_trait]
pub trait ContainerRepository: Repository<Container> {
    /// Find containers by various filters.
    async fn find_by_status(&self, status: ContainerStatus) -> Result<Vec<Container>, RepositoryError>;

    /// Find containers using a specific image.
    async fn find_by_image(&self, image_id: &ImageId) -> Result<Vec<Container>, RepositoryError>;

    /// Find container by name (unique).
    async fn find_by_name(&self, name: &ContainerName) -> Result<Option<Container>, RepositoryError>;

    /// List all containers with optional filters.
    async fn list(&self, filter: ContainerFilter) -> Result<Vec<Container>, RepositoryError>;

    /// Get container count by status.
    async fn count_by_status(&self) -> Result<HashMap<ContainerStatus, usize>, RepositoryError>;

    /// Update container status atomically.
    async fn update_status(
        &self,
        id: &ContainerId,
        old_status: ContainerStatus,
        new_status: ContainerStatus,
    ) -> Result<bool, RepositoryError>;
}

/// Filter criteria for container listing.
#[derive(Debug, Clone, Default)]
pub struct ContainerFilter {
    pub status: Option<Vec<ContainerStatus>>,
    pub image_id: Option<ImageId>,
    pub labels: HashMap<String, String>,
    pub name_pattern: Option<String>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}
```

### Implementation: In-Memory Container Repository

```rust
use std::collections::HashMap;
use tokio::sync::RwLock;

/// In-memory container repository for testing and ephemeral mode.
pub struct InMemoryContainerRepository {
    containers: RwLock<HashMap<ContainerId, Container>>,
    name_index: RwLock<HashMap<ContainerName, ContainerId>>,
}

impl InMemoryContainerRepository {
    pub fn new() -> Self {
        Self {
            containers: RwLock::new(HashMap::new()),
            name_index: RwLock::new(HashMap::new()),
        }
    }
}

#[async_trait]
impl ContainerRepository for InMemoryContainerRepository {
    async fn find(&self, id: &ContainerId) -> Result<Option<Container>, RepositoryError> {
        let containers = self.containers.read().await;
        Ok(containers.get(id).cloned())
    }

    async fn save(&self, container: &Container) -> Result<(), RepositoryError> {
        let mut containers = self.containers.write().await;
        let mut name_index = self.name_index.write().await;

        // Update name index if name exists
        if let Some(name) = &container.name {
            name_index.insert(name.clone(), container.id().clone());
        }

        containers.insert(container.id().clone(), container.clone());
        Ok(())
    }

    async fn delete(&self, id: &ContainerId) -> Result<(), RepositoryError> {
        let mut containers = self.containers.write().await;
        let mut name_index = self.name_index.write().await;

        if let Some(container) = containers.remove(id) {
            if let Some(name) = &container.name {
                name_index.remove(name);
            }
        }

        Ok(())
    }

    async fn find_by_name(&self, name: &ContainerName) -> Result<Option<Container>, RepositoryError> {
        let name_index = self.name_index.read().await;
        if let Some(id) = name_index.get(name) {
            self.find(id).await
        } else {
            Ok(None)
        }
    }

    async fn find_by_status(&self, status: ContainerStatus) -> Result<Vec<Container>, RepositoryError> {
        let containers = self.containers.read().await;
        Ok(containers.values()
            .filter(|c| c.status() == status)
            .cloned()
            .collect())
    }

    async fn list(&self, filter: ContainerFilter) -> Result<Vec<Container>, RepositoryError> {
        let containers = self.containers.read().await;
        let mut result: Vec<_> = containers.values()
            .filter(|c| {
                if let Some(ref statuses) = filter.status {
                    if !statuses.contains(&c.status()) {
                        return false;
                    }
                }
                if let Some(ref image_id) = filter.image_id {
                    if c.image_id() != *image_id {
                        return false;
                    }
                }
                // ... more filter logic
                true
            })
            .cloned()
            .collect();

        if let Some(limit) = filter.limit {
            result.truncate(limit);
        }

        Ok(result)
    }
}
```

### Implementation: SQLite Container Repository

```rust
use sqlx::SqlitePool;

/// SQLite-backed container repository for persistence.
pub struct SqliteContainerRepository {
    pool: SqlitePool,
}

impl SqliteContainerRepository {
    pub async fn new(pool: SqlitePool) -> Result<Self, sqlx::Error> {
        // Run migrations
        sqlx::query(r#"
            CREATE TABLE IF NOT EXISTS containers (
                id TEXT PRIMARY KEY,
                name TEXT UNIQUE,
                image_id TEXT NOT NULL,
                status TEXT NOT NULL,
                spec_json TEXT NOT NULL,
                state_json TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_containers_status ON containers(status);
            CREATE INDEX IF NOT EXISTS idx_containers_image ON containers(image_id);
        "#).execute(&pool).await?;

        Ok(Self { pool })
    }
}

#[async_trait]
impl ContainerRepository for SqliteContainerRepository {
    async fn find(&self, id: &ContainerId) -> Result<Option<Container>, RepositoryError> {
        let row = sqlx::query_as::<_, ContainerRow>(
            "SELECT * FROM containers WHERE id = ?"
        )
        .bind(id.to_string())
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some(r) => Ok(Some(r.into_container()?)),
            None => Ok(None),
        }
    }

    async fn save(&self, container: &Container) -> Result<(), RepositoryError> {
        let row = ContainerRow::from_container(container)?;

        sqlx::query(r#"
            INSERT INTO containers (id, name, image_id, status, spec_json, state_json, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                status = excluded.status,
                state_json = excluded.state_json,
                updated_at = excluded.updated_at
        "#)
        .bind(&row.id)
        .bind(&row.name)
        .bind(&row.image_id)
        .bind(&row.status)
        .bind(&row.spec_json)
        .bind(&row.state_json)
        .bind(row.created_at)
        .bind(row.updated_at)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn delete(&self, id: &ContainerId) -> Result<(), RepositoryError> {
        sqlx::query("DELETE FROM containers WHERE id = ?")
            .bind(id.to_string())
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    // ... other methods
}
```

---

## Image Repository

```rust
/// Repository for Image aggregates.
#[async_trait]
pub trait ImageRepository: Repository<Image> {
    /// Find image by digest.
    async fn find_by_digest(&self, digest: &ImageDigest) -> Result<Option<Image>, RepositoryError>;

    /// Find image by tag.
    async fn find_by_tag(&self, tag: &ImageTag) -> Result<Option<Image>, RepositoryError>;

    /// List all images.
    async fn list(&self) -> Result<Vec<Image>, RepositoryError>;

    /// Add tag to image.
    async fn tag(&self, image_id: &ImageId, tag: ImageTag) -> Result<(), RepositoryError>;

    /// Remove tag from image.
    async fn untag(&self, tag: &ImageTag) -> Result<bool, RepositoryError>;

    /// Find images with a specific label.
    async fn find_by_label(&self, key: &str, value: &str) -> Result<Vec<Image>, RepositoryError>;

    /// Get dangling images (untagged, not used by any container).
    async fn find_dangling(&self) -> Result<Vec<Image>, RepositoryError>;

    /// Get total disk usage.
    async fn disk_usage(&self) -> Result<Bytes, RepositoryError>;
}
```

---

## Volume Repository

```rust
/// Repository for Volume aggregates.
#[async_trait]
pub trait VolumeRepository: Repository<Volume> {
    /// Find volume by name.
    async fn find_by_name(&self, name: &VolumeName) -> Result<Option<Volume>, RepositoryError>;

    /// List all volumes.
    async fn list(&self) -> Result<Vec<Volume>, RepositoryError>;

    /// Find volumes with a specific label.
    async fn find_by_label(&self, key: &str, value: &str) -> Result<Vec<Volume>, RepositoryError>;

    /// Find volumes not in use by any container.
    async fn find_unused(&self) -> Result<Vec<Volume>, RepositoryError>;

    /// Get total disk usage.
    async fn disk_usage(&self) -> Result<Bytes, RepositoryError>;

    /// Check if volume is in use.
    async fn is_in_use(&self, volume_id: &VolumeId) -> Result<bool, RepositoryError>;
}
```

---

## Network Repository

```rust
/// Repository for Network aggregates.
#[async_trait]
pub trait NetworkRepository: Repository<Network> {
    /// Find network by name.
    async fn find_by_name(&self, name: &NetworkName) -> Result<Option<Network>, RepositoryError>;

    /// List all networks.
    async fn list(&self) -> Result<Vec<Network>, RepositoryError>;

    /// Find networks with a specific label.
    async fn find_by_label(&self, key: &str, value: &str) -> Result<Vec<Network>, RepositoryError>;

    /// Find networks of a specific driver type.
    async fn find_by_driver(&self, driver: NetworkDriver) -> Result<Vec<Network>, RepositoryError>;

    /// Check if network has connected containers.
    async fn has_containers(&self, network_id: &NetworkId) -> Result<bool, RepositoryError>;
}
```

---

## Layer Repository (Internal to ImageManagement)

```rust
/// Repository for Layer value objects (internal to image management).
#[async_trait]
pub trait LayerRepository: Send + Sync {
    /// Get layer by hash.
    async fn get(&self, hash: &LayerHash) -> Result<Option<Layer>, RepositoryError>;

    /// Store a new layer.
    async fn store(&self, layer: Layer, data: &[u8]) -> Result<(), RepositoryError>;

    /// Delete a layer.
    async fn delete(&self, hash: &LayerHash) -> Result<(), RepositoryError>;

    /// Check if layer exists.
    async fn exists(&self, hash: &LayerHash) -> Result<bool, RepositoryError>;

    /// Get layer data path.
    async fn data_path(&self, hash: &LayerHash) -> Result<PathBuf, RepositoryError>;

    /// Get layer size.
    async fn size(&self, hash: &LayerHash) -> Result<Bytes, RepositoryError>;

    /// Find layers not referenced by any image.
    async fn find_orphaned(&self) -> Result<Vec<LayerHash>, RepositoryError>;

    /// Get total storage used.
    async fn total_size(&self) -> Result<Bytes, RepositoryError>;
}
```

---

## Build Repository

```rust
/// Repository for Build aggregates (for build history and caching).
#[async_trait]
pub trait BuildRepository: Repository<Build> {
    /// Find builds by status.
    async fn find_by_status(&self, status: BuildStatus) -> Result<Vec<Build>, RepositoryError>;

    /// Find recent builds.
    async fn find_recent(&self, limit: usize) -> Result<Vec<Build>, RepositoryError>;

    /// Find build by image ID (if successful).
    async fn find_by_image(&self, image_id: &ImageId) -> Result<Option<Build>, RepositoryError>;

    /// Get cache key -> layer hash mapping.
    async fn get_cache_entry(&self, key: &BuildCacheKey) -> Result<Option<LayerHash>, RepositoryError>;

    /// Set cache entry.
    async fn set_cache_entry(&self, key: BuildCacheKey, hash: LayerHash) -> Result<(), RepositoryError>;

    /// Invalidate cache entries matching pattern.
    async fn invalidate_cache(&self, pattern: &str) -> Result<usize, RepositoryError>;
}
```

---

## Repository Factory

```rust
/// Factory for creating repository instances.
pub struct RepositoryFactory {
    config: RepositoryConfig,
}

#[derive(Debug, Clone)]
pub enum RepositoryConfig {
    InMemory,
    Sqlite { path: PathBuf },
    Postgres { url: String },
}

impl RepositoryFactory {
    pub fn new(config: RepositoryConfig) -> Self {
        Self { config }
    }

    pub async fn container_repository(&self) -> Result<Arc<dyn ContainerRepository>, RepositoryError> {
        match &self.config {
            RepositoryConfig::InMemory => Ok(Arc::new(InMemoryContainerRepository::new())),
            RepositoryConfig::Sqlite { path } => {
                let pool = SqlitePool::connect(&format!("sqlite:{}", path.display())).await?;
                Ok(Arc::new(SqliteContainerRepository::new(pool).await?))
            }
            _ => Err(RepositoryError::UnsupportedBackend),
        }
    }

    pub async fn image_repository(&self) -> Result<Arc<dyn ImageRepository>, RepositoryError> {
        // Similar pattern
    }

    pub async fn volume_repository(&self) -> Result<Arc<dyn VolumeRepository>, RepositoryError> {
        // Similar pattern
    }

    pub async fn network_repository(&self) -> Result<Arc<dyn NetworkRepository>, RepositoryError> {
        // Similar pattern
    }
}
```

---

## Error Types

```rust
/// Repository error types.
#[derive(Debug, thiserror::Error)]
pub enum RepositoryError {
    #[error("Entity not found: {0}")]
    NotFound(String),

    #[error("Entity already exists: {0}")]
    AlreadyExists(String),

    #[error("Optimistic lock failed: expected version {expected}, got {actual}")]
    OptimisticLock { expected: u64, actual: u64 },

    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Connection error: {0}")]
    Connection(String),

    #[error("Transaction failed: {0}")]
    Transaction(String),

    #[error("Unsupported backend")]
    UnsupportedBackend,

    #[error("Invalid query: {0}")]
    InvalidQuery(String),
}
```

---

## Unit of Work Pattern

```rust
/// Unit of work for transactional operations across repositories.
#[async_trait]
pub trait UnitOfWork: Send + Sync {
    type Error: std::error::Error + Send + Sync + 'static;

    /// Commit all changes.
    async fn commit(self) -> Result<(), Self::Error>;

    /// Rollback all changes.
    async fn rollback(self) -> Result<(), Self::Error>;

    /// Get container repository within this unit of work.
    fn containers(&mut self) -> &mut dyn ContainerRepository;

    /// Get image repository within this unit of work.
    fn images(&mut self) -> &mut dyn ImageRepository;
}

/// Unit of work factory.
#[async_trait]
pub trait UnitOfWorkFactory: Send + Sync {
    type Uow: UnitOfWork;

    /// Begin a new unit of work.
    async fn begin(&self) -> Result<Self::Uow, RepositoryError>;
}
```

---

## Repository Summary

| Repository | Aggregate | Key Methods |
|------------|-----------|-------------|
| ContainerRepository | Container | find, save, delete, find_by_status, find_by_name, list |
| ImageRepository | Image | find_by_digest, find_by_tag, tag, untag, find_dangling |
| VolumeRepository | Volume | find_by_name, find_unused, disk_usage, is_in_use |
| NetworkRepository | Network | find_by_name, find_by_driver, has_containers |
| LayerRepository | Layer | store, get, delete, find_orphaned |
| BuildRepository | Build | get_cache_entry, set_cache_entry, invalidate_cache |

All repositories:
- Define interfaces as Rust traits
- Return owned aggregate instances
- Use async for I/O operations
- Return Result with domain-specific errors
- Support multiple implementations (in-memory, SQLite, PostgreSQL)
