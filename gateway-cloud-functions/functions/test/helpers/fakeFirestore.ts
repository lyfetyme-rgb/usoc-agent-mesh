/* Minimal in-memory Firestore double used by handler tests. */

type DocData = Record<string, any>;

const DELETE_SENTINEL = { __fakeDelete: true };

export function fakeTimestamp(millis: number): any {
  return {
    toMillis: () => millis,
    toDate: () => new Date(millis),
    isEqual: (other: any) => other?.toMillis?.() === millis,
  };
}

function clone<T>(value: T): T {
  if (value === null || typeof value !== "object") return value;
  // Firestore timestamps carry methods; keep them intact rather than stringifying.
  if (typeof (value as any).toMillis === "function") return value;
  if (Array.isArray(value)) return value.map((item) => clone(item)) as T;
  const result: Record<string, unknown> = {};
  for (const [key, item] of Object.entries(value)) result[key] = clone(item);
  return result as T;
}

function applyUpdate(current: DocData, update: DocData): DocData {
  const next = { ...current };
  for (const [key, value] of Object.entries(update)) {
    if (value && typeof value === "object" && (value as any).__fakeDelete) delete next[key];
    else next[key] = clone(value);
  }
  return next;
}

export class FakeSnap {
  constructor(
    private readonly value: DocData | undefined,
    public readonly ref: FakeDocRef,
  ) {}

  get exists(): boolean {
    return this.value !== undefined;
  }

  get id(): string {
    return this.ref.id;
  }

  data(): DocData | undefined {
    return this.value === undefined ? undefined : clone(this.value);
  }
}

export class FakeDocRef {
  constructor(
    public readonly db: FakeFirestore,
    public readonly path: string,
    public readonly parent?: FakeCollectionRef,
  ) {}

  get id(): string {
    return this.path.split("/").pop() ?? "";
  }

  collection(name: string): FakeCollectionRef {
    return new FakeCollectionRef(this.db, `${this.path}/${name}`, this);
  }

  get(): Promise<FakeSnap> {
    return Promise.resolve(new FakeSnap(this.db.store.get(this.path), this));
  }

  set(data: DocData): Promise<void> {
    this.db.store.set(this.path, clone(data));
    return Promise.resolve();
  }

  update(data: DocData): Promise<void> {
    const current = this.db.store.get(this.path);
    if (!current) throw new Error(`Missing document ${this.path}`);
    this.db.store.set(this.path, applyUpdate(current, data));
    return Promise.resolve();
  }

  delete(): Promise<void> {
    this.db.store.delete(this.path);
    return Promise.resolve();
  }
}

export class FakeQuery {
  private filters: Array<{ field: string; op: string; value: any }> = [];

  constructor(
    private readonly db: FakeFirestore,
    private readonly paths: string[],
  ) {}

  where(field: string, op: string, value: any): this {
    this.filters.push({ field, op, value });
    return this;
  }

  get(): Promise<{ docs: FakeSnap[] }> {
    const docs = this.paths
      .map((path) => new FakeSnap(this.db.store.get(path), this.db.doc(path)))
      .filter((snap) => snap.exists)
      .filter((snap) =>
        this.filters.every(({ field, op, value }) => {
          const actual = snap.data()?.[field];
          if (actual === undefined) return false;
          const left = typeof actual?.toMillis === "function" ? actual.toMillis() : actual;
          const right = typeof value?.toMillis === "function" ? value.toMillis() : value;
          if (op === "<") return left < right;
          if (op === "<=") return left <= right;
          if (op === ">") return left > right;
          if (op === ">=") return left >= right;
          if (op === "==") return left === right;
          return false;
        }),
      );
    return Promise.resolve({ docs });
  }
}

export class FakeCollectionRef {
  constructor(
    public readonly db: FakeFirestore,
    public readonly path: string,
    public readonly parent?: FakeDocRef,
  ) {}

  doc(id?: string): FakeDocRef {
    const docId = id ?? this.db.nextId();
    return new FakeDocRef(this.db, `${this.path}/${docId}`, this);
  }

  where(field: string, op: string, value: any): FakeQuery {
    return new FakeQuery(this.db, this.listPaths()).where(field, op, value);
  }

  get(): Promise<{ docs: FakeSnap[] }> {
    return new FakeQuery(this.db, this.listPaths()).get();
  }

  private listPaths(): string[] {
    const prefix = `${this.path}/`;
    return [...this.db.store.keys()]
      .filter((path) => path.startsWith(prefix))
      .filter((path) => !path.slice(prefix.length).includes("/"));
  }
}

export class FakeBatch {
  private readonly ops: Array<() => void> = [];
  /** Exposed so tests can assert the 500-operation Firestore batch ceiling. */
  get opCount(): number {
    return this.ops.length;
  }

  constructor(private readonly db: FakeFirestore) {}

  set(ref: FakeDocRef, data: DocData): this {
    this.ops.push(() => this.db.store.set(ref.path, clone(data)));
    return this;
  }

  update(ref: FakeDocRef, data: DocData): this {
    this.ops.push(() => {
      const current = this.db.store.get(ref.path);
      if (!current) throw new Error(`Missing document ${ref.path}`);
      this.db.store.set(ref.path, applyUpdate(current, data));
    });
    return this;
  }

  delete(ref: FakeDocRef): this {
    this.ops.push(() => this.db.store.delete(ref.path));
    return this;
  }

  commit(): Promise<void> {
    this.ops.forEach((op) => op());
    return Promise.resolve();
  }
}

export class FakeFirestore {
  readonly store = new Map<string, DocData>();
  /** Every batch created by the code under test, for batch-size assertions. */
  readonly batches: FakeBatch[] = [];
  private counter = 0;

  nextId(): string {
    this.counter += 1;
    return `auto_${this.counter}`;
  }

  doc(path: string): FakeDocRef {
    const segments = path.split("/");
    const docId = segments.pop() ?? "";
    const collectionPath = segments.join("/");
    const parentSegments = collectionPath.split("/");
    parentSegments.pop();
    const grandParentPath = parentSegments.join("/");
    const parent =
      grandParentPath.length > 0
        ? new FakeDocRef(this, grandParentPath)
        : undefined;
    return new FakeDocRef(this, path, new FakeCollectionRef(this, collectionPath, parent));
  }

  collection(path: string): FakeCollectionRef {
    const segments = path.split("/");
    const collectionId = segments.pop() ?? "";
    const parentPath = segments.join("/");
    const parent = parentPath.length > 0 ? new FakeDocRef(this, parentPath) : undefined;
    return new FakeCollectionRef(this, path, parent);
  }

  collectionGroup(name: string): FakeQuery {
    const paths = [...this.store.keys()].filter((path) => {
      const segments = path.split("/");
      return segments.length >= 2 && segments[segments.length - 2] === name;
    });
    return new FakeQuery(this, paths);
  }

  batch(): FakeBatch {
    const batch = new FakeBatch(this);
    this.batches.push(batch);
    return batch;
  }

  async runTransaction<T>(fn: (tx: any) => Promise<T>): Promise<T> {
    const snapshot = new Map(this.store);
    const ops: Array<() => void> = [];
    const tx = {
      get: (ref: FakeDocRef) =>
        Promise.resolve(new FakeSnap(snapshot.get(ref.path), ref)),
      set: (ref: FakeDocRef, data: DocData) => {
        ops.push(() => this.store.set(ref.path, clone(data)));
      },
      update: (ref: FakeDocRef, data: DocData) => {
        ops.push(() => {
          const current = this.store.get(ref.path);
          if (!current) throw new Error(`Missing document ${ref.path}`);
          this.store.set(ref.path, applyUpdate(current, data));
        });
      },
      delete: (ref: FakeDocRef) => {
        ops.push(() => this.store.delete(ref.path));
      },
    };
    const result = await fn(tx);
    ops.forEach((op) => op());
    return result;
  }
}

export const fakePaths = {
  tenants: "tenants",
  technicians: "technicians",
  alerts: "alerts",
  customerRequests: "customerRequests",
  gatewayTokens: "gatewayTokens",
  tenant: (tenantId: string) => `tenants/${tenantId}`,
  gateway: (tenantId: string, gatewayId: string) => `tenants/${tenantId}/gateways/${gatewayId}`,
  packets: (tenantId: string, gatewayId: string) =>
    `tenants/${tenantId}/gateways/${gatewayId}/packets`,
  rollups: (tenantId: string, gatewayId: string) =>
    `tenants/${tenantId}/gateways/${gatewayId}/rollups`,
};
