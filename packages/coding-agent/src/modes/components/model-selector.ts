import { ThinkingLevel } from "@gajae-code/agent-core";
import { type Model, modelsAreEqual } from "@gajae-code/ai";
import { getOAuthProviders } from "@gajae-code/ai/utils/oauth";
import {
	Container,
	fuzzyFilter,
	getKeybindings,
	Input,
	matchesKey,
	Spacer,
	type Tab,
	TabBar,
	Text,
	type TUI,
} from "@gajae-code/tui";
import type { ModelRegistry } from "../../config/model-registry";
import { getRoleInfo } from "../../config/model-registry";
import { resolveModelRoleValue } from "../../config/model-resolver";
import type { Settings } from "../../config/settings";
import { type ThemeColor, theme } from "../../modes/theme/theme";
import { getThinkingLevelMetadata } from "../../thinking";
import { getTabBarTheme } from "../shared";
import { DynamicBorder } from "./dynamic-border";

function makeInvertedBadge(label: string, color: ThemeColor): string {
	const fgAnsi = theme.getFgAnsi(color);
	const bgAnsi = fgAnsi.replace(/\x1b\[38;/g, "\x1b[48;");
	return `${bgAnsi}\x1b[30m ${label} \x1b[39m\x1b[49m`;
}

function normalizeSearchText(value: string): string {
	return value
		.toLowerCase()
		.replace(/[^a-z0-9]+/g, " ")
		.trim();
}

function compactSearchText(value: string): string {
	return value.toLowerCase().replace(/[^a-z0-9]+/g, "");
}

function computeModelRank(model: Model, roles: Record<string, RoleAssignment | undefined>): number {
	return roles.default && modelsAreEqual(roles.default.model, model) ? 0 : 1;
}

function computeAvailabilityRank(availability: ModelAvailability): number {
	return availability.status === "ready" ? 0 : 1;
}

function getModelSearchText(item: ModelItem): string {
	return `${item.provider}/${item.id} ${item.provider} ${item.id} ${item.model.name}`;
}

function requiresAdvancedProviderSetup(baseUrl: string | undefined): boolean {
	if (!baseUrl) return false;
	return /[<{]/.test(baseUrl) || /^https?:\/\/(?:localhost|127\.0\.0\.1|\[::1\])(?::|\/|$)/i.test(baseUrl);
}

type ModelAvailability =
	| { status: "ready" }
	| { status: "unavailable"; reason: string; action?: string; setup?: ModelSetupAction };

type ModelSetupAction =
	| { kind: "api_key_prompt"; provider: string }
	| { kind: "oauth_login"; provider: string }
	| { kind: "manual"; message: string };

interface ModelItem {
	kind: "provider";
	provider: string;
	id: string;
	model: Model;
	selector: string;
	availability: ModelAvailability;
}

interface CanonicalModelItem {
	kind: "canonical";
	id: string;
	model: Model;
	selector: string;
	variantCount: number;
	searchText: string;
	normalizedSearchText: string;
	compactSearchText: string;
	availability: ModelAvailability;
}

interface ScopedModelItem {
	model: Model;
	thinkingLevel?: string;
}

interface RoleAssignment {
	model: Model;
	thinkingLevel: ThinkingLevel;
}

type RoleSelectCallback = (
	model: Model,
	role: "default" | null,
	thinkingLevel?: ThinkingLevel,
	selector?: string,
) => void;
type CancelCallback = () => void;

interface ProviderTabState {
	id: string;
	label: string;
	providerId?: string;
}
const CANONICAL_TAB = "CANONICAL";

const STATIC_PROVIDER_TABS: ProviderTabState[] = [{ id: CANONICAL_TAB, label: CANONICAL_TAB }];

function formatProviderTabLabel(providerId: string): string {
	return providerId.replace(/[-_]+/g, " ").toUpperCase();
}

function createProviderTab(providerId: string): ProviderTabState {
	return { id: providerId, label: formatProviderTabLabel(providerId), providerId };
}
/**
 * Component that renders a canonical model selector with provider tabs.
 * - Tab/Arrow Left/Right: Switch between provider tabs
 * - Arrow Up/Down: Navigate model list
 * - Enter: Select the highlighted model as the canonical/default model
 * - Escape: Close selector
 */
export class ModelSelectorComponent extends Container {
	#searchInput: Input;
	#headerContainer: Container;
	#tabBar: TabBar | null = null;
	#listContainer: Container;
	#allModels: ModelItem[] = [];
	#filteredModels: ModelItem[] = [];
	#canonicalModels: CanonicalModelItem[] = [];
	#filteredCanonicalModels: CanonicalModelItem[] = [];
	#selectedIndex: number = 0;
	#roles = {} as Record<string, RoleAssignment | undefined>;
	#settings = null as unknown as Settings;
	#modelRegistry = null as unknown as ModelRegistry;
	#onSelectCallback = (() => {}) as RoleSelectCallback;
	#onCancelCallback = (() => {}) as CancelCallback;
	#errorMessage?: unknown;
	#tui: TUI;
	#scopedModels: ReadonlyArray<ScopedModelItem>;
	#temporaryOnly: boolean;
	#onLoginProviderCallback?: (providerId: string) => Promise<boolean>;

	// Tab state
	#providers: ProviderTabState[] = STATIC_PROVIDER_TABS;
	#activeTabIndex: number = 0;

	constructor(
		tui: TUI,
		_currentModel: Model | undefined,
		settings: Settings,
		modelRegistry: ModelRegistry,
		scopedModels: ReadonlyArray<ScopedModelItem>,
		onSelect: (model: Model, role: "default" | null, thinkingLevel?: ThinkingLevel, selector?: string) => void,
		onCancel: () => void,
		options?: {
			temporaryOnly?: boolean;
			initialSearchInput?: string;
			onLoginProvider?: (providerId: string) => Promise<boolean>;
		},
	) {
		super();

		this.#tui = tui;
		this.#settings = settings;
		this.#modelRegistry = modelRegistry;
		this.#scopedModels = scopedModels;
		this.#onSelectCallback = onSelect;
		this.#onCancelCallback = onCancel;
		this.#temporaryOnly = options?.temporaryOnly ?? false;
		this.#onLoginProviderCallback = options?.onLoginProvider;
		const initialSearchInput = options?.initialSearchInput;

		// Load current role assignments from settings
		this.#loadRoleModels();

		// Add top border
		this.addChild(new DynamicBorder());
		this.addChild(new Spacer(1));

		// Add hint about model filtering
		const hintText =
			scopedModels.length > 0
				? "Showing models from --models scope"
				: "Type to search all models. Enter selects or opens setup. Tab switches providers.";
		this.addChild(new Text(theme.fg("warning", hintText), 0, 0));
		this.addChild(new Spacer(1));

		// Create header container for tab bar
		this.#headerContainer = new Container();
		this.addChild(this.#headerContainer);

		this.addChild(new Spacer(1));

		// Create search input
		this.#searchInput = new Input();
		if (initialSearchInput) {
			this.#searchInput.setValue(initialSearchInput);
		}
		this.#searchInput.onSubmit = () => {
			const selectedItem = this.#getSelectedItem();
			if (selectedItem) {
				this.#handleSelect(selectedItem, this.#temporaryOnly ? null : "default");
			}
		};
		this.addChild(this.#searchInput);

		this.addChild(new Spacer(1));

		// Create list container
		this.#listContainer = new Container();
		this.addChild(this.#listContainer);

		this.addChild(new Spacer(1));

		// Add bottom border
		this.addChild(new DynamicBorder());

		// Load models and do initial render
		this.#loadModels().then(() => {
			this.#buildProviderTabs();
			this.#updateTabBar();
			// Always apply the current search query — the user may have typed
			// while models were loading asynchronously.
			const currentQuery = this.#searchInput.getValue();
			if (currentQuery) {
				this.#filterModels(currentQuery);
			} else {
				this.#updateList();
			}
			// Request re-render after models are loaded
			this.#tui.requestRender();
		});
	}

	#loadRoleModels(): void {
		const allModels = this.#modelRegistry.getAll();
		const matchPreferences = { usageOrder: this.#settings.getStorage()?.getModelUsageOrder() };
		for (const role of ["default"]) {
			const roleValue = this.#settings.getModelRole(role);
			if (!roleValue) continue;

			const resolved = resolveModelRoleValue(roleValue, allModels, {
				settings: this.#settings,
				matchPreferences,
				modelRegistry: this.#modelRegistry,
			});
			if (resolved.model) {
				this.#roles[role] = {
					model: resolved.model,
					thinkingLevel:
						resolved.explicitThinkingLevel && resolved.thinkingLevel !== undefined
							? resolved.thinkingLevel
							: ThinkingLevel.Inherit,
				};
			}
		}
	}

	#sortModels(models: ModelItem[]): void {
		// Sort: default-tagged model first, then MRU, then alphabetical
		const mruOrder = this.#settings.getStorage()?.getModelUsageOrder() ?? [];
		const mruIndex = new Map(mruOrder.map((key, i) => [key, i]));

		const modelRank = (item: ModelItem) => computeModelRank(item.model, this.#roles);

		const dateRe = /-(\d{8})$/;
		const latestRe = /-latest$/;

		models.sort((a, b) => {
			const aKey = a.selector;
			const bKey = b.selector;

			const aRank = modelRank(a);
			const bRank = modelRank(b);
			if (aRank !== bRank) return aRank - bRank;

			// Then MRU order (models in mruIndex come before those not in it)
			const aMru = mruIndex.get(aKey) ?? Number.MAX_SAFE_INTEGER;
			const bMru = mruIndex.get(bKey) ?? Number.MAX_SAFE_INTEGER;
			if (aMru !== bMru) return aMru - bMru;

			// By provider, then recency within provider
			const providerCmp = a.provider.localeCompare(b.provider);
			if (providerCmp !== 0) return providerCmp;

			// Priority field (lower = better, e.g. OpenAI code backend priority values)
			const aPri = a.model.priority ?? Number.MAX_SAFE_INTEGER;
			const bPri = b.model.priority ?? Number.MAX_SAFE_INTEGER;
			if (aPri !== bPri) return aPri - bPri;

			// Version number descending (higher version = better model)
			const aVer = extractVersionNumber(a.id);
			const bVer = extractVersionNumber(b.id);
			if (aVer !== bVer) return bVer - aVer;

			const aIsLatest = latestRe.test(a.id);
			const bIsLatest = latestRe.test(b.id);
			const aDate = a.id.match(dateRe)?.[1] ?? "";
			const bDate = b.id.match(dateRe)?.[1] ?? "";

			// Both have dates or latest tags — sort by recency
			const aHasRecency = aIsLatest || aDate !== "";
			const bHasRecency = bIsLatest || bDate !== "";

			// Models with recency info come before those without
			if (aHasRecency !== bHasRecency) return aHasRecency ? -1 : 1;

			// If neither has recency info, fall back to alphabetical
			if (!aHasRecency) return a.id.localeCompare(b.id);

			// -latest always sorts first within recency group
			if (aIsLatest !== bIsLatest) return aIsLatest ? -1 : 1;

			// Both have dates — descending (newest first)
			if (aDate && bDate) return bDate.localeCompare(aDate);

			// One has date, other is latest — latest first
			return aIsLatest ? -1 : bIsLatest ? 1 : a.id.localeCompare(b.id);
		});
	}

	#sortCanonicalModels(models: CanonicalModelItem[]): void {
		const mruOrder = this.#settings.getStorage()?.getModelUsageOrder() ?? [];
		const mruIndex = new Map(mruOrder.map((key, i) => [key, i]));

		const modelRank = (item: CanonicalModelItem) => computeModelRank(item.model, this.#roles);

		models.sort((a, b) => {
			const aRank = modelRank(a);
			const bRank = modelRank(b);
			if (aRank !== bRank) return aRank - bRank;

			const aMru = mruIndex.get(`${a.model.provider}/${a.model.id}`) ?? Number.MAX_SAFE_INTEGER;
			const bMru = mruIndex.get(`${b.model.provider}/${b.model.id}`) ?? Number.MAX_SAFE_INTEGER;
			if (aMru !== bMru) return aMru - bMru;

			const providerCmp = a.model.provider.localeCompare(b.model.provider);
			if (providerCmp !== 0) return providerCmp;

			return a.id.localeCompare(b.id);
		});
	}

	#sortSearchModels(models: ModelItem[], query: string): void {
		const normalizedQuery = normalizeSearchText(query);
		const compactQuery = compactSearchText(query);
		const rank = (item: ModelItem): number => {
			const selector = item.selector.toLowerCase();
			const id = item.id.toLowerCase();
			const provider = item.provider.toLowerCase();
			const name = item.model.name.toLowerCase();
			const normalized = normalizeSearchText(getModelSearchText(item));
			const compact = compactSearchText(getModelSearchText(item));
			if (selector === normalizedQuery || id === normalizedQuery) return 0;
			if (provider === normalizedQuery) return 1;
			if (provider.startsWith(normalizedQuery)) return 2;
			if (id.startsWith(normalizedQuery) || selector.startsWith(normalizedQuery)) return 3;
			if (provider.includes(normalizedQuery)) return 4;
			if (id.includes(normalizedQuery) || selector.includes(normalizedQuery)) return 5;
			if (name.includes(normalizedQuery)) return 6;
			if (compactQuery && compact.includes(compactQuery)) return 7;
			if (normalized.includes(normalizedQuery)) return 8;
			return 9;
		};
		models.sort((a, b) => {
			const aRank = rank(a);
			const bRank = rank(b);
			if (aRank !== bRank) return aRank - bRank;
			const aAvailability = computeAvailabilityRank(a.availability);
			const bAvailability = computeAvailabilityRank(b.availability);
			if (aAvailability !== bAvailability) return aAvailability - bAvailability;
			const providerCmp = a.provider.localeCompare(b.provider);
			if (providerCmp !== 0) return providerCmp;
			return a.id.localeCompare(b.id);
		});
	}

	#resolveModelAvailability(model: Model, availableSelectors: Set<string>): ModelAvailability {
		const selector = `${model.provider}/${model.id}`;
		if (availableSelectors.has(selector)) return { status: "ready" };

		const disabledProviders = new Set(this.#settings.get("disabledProviders") ?? []);
		if (disabledProviders.has(model.provider)) {
			return {
				status: "unavailable",
				reason: "Disabled in settings",
				action: "Remove it from disabledProviders to use this model",
			};
		}

		const oauthProvider = getOAuthProviders().find(provider => provider.id === model.provider);
		if (oauthProvider) {
			return {
				status: "unavailable",
				reason: "Login required",
				action: "Press Enter to login or re-login",
				setup: { kind: "oauth_login", provider: model.provider },
			};
		}

		if (!this.#modelRegistry.hasConfiguredAuth(model)) {
			const baseUrl = model.baseUrl ?? this.#modelRegistry.getProviderBaseUrl(model.provider);
			if (requiresAdvancedProviderSetup(baseUrl)) {
				return {
					status: "unavailable",
					reason: "Provider setup required",
					action: "Use /provider add to configure endpoint and credentials",
					setup: { kind: "manual", message: "Use /provider add to configure endpoint and credentials" },
				};
			}
			return {
				status: "unavailable",
				reason: "API key or provider config required",
				action: "Use /provider add or set an API key for this provider",
				setup: { kind: "api_key_prompt", provider: model.provider },
			};
		}

		return { status: "unavailable", reason: "Unavailable", action: "Check provider settings and credentials" };
	}

	async #loadModels(): Promise<void> {
		let models: ModelItem[];

		// Use scoped models if provided via --models flag
		if (this.#scopedModels.length > 0) {
			models = this.#scopedModels.map(scoped => ({
				kind: "provider",
				provider: scoped.model.provider,
				id: scoped.model.id,
				model: scoped.model,
				selector: `${scoped.model.provider}/${scoped.model.id}`,
				availability: { status: "ready" },
			}));
		} else {
			// Reload config and cached discovery state without blocking on live provider refresh
			await this.#modelRegistry.refresh("offline");

			// Check for models.json errors
			const loadError = this.#modelRegistry.getError();
			if (loadError) {
				this.#errorMessage = loadError;
			} else {
				this.#errorMessage = undefined;
			}

			// Show the whole bundled/configured catalog, not only authenticated models.
			try {
				const availableSelectors = new Set(
					this.#modelRegistry.getAvailable().map(model => `${model.provider}/${model.id}`),
				);
				models = this.#modelRegistry.getAll().map((model: Model) => ({
					kind: "provider",
					provider: model.provider,
					id: model.id,
					model,
					selector: `${model.provider}/${model.id}`,
					availability: this.#resolveModelAvailability(model, availableSelectors),
				}));
			} catch (error) {
				this.#allModels = [];
				this.#filteredModels = [];
				this.#canonicalModels = [];
				this.#filteredCanonicalModels = [];
				this.#errorMessage = error instanceof Error ? error.message : String(error);
				return;
			}
		}

		const modelsBySelector = new Map(models.map(item => [item.selector, item]));
		const canonicalCandidateItems =
			this.#scopedModels.length > 0 ? models : models.filter(item => item.availability.status === "ready");
		const candidateModels = canonicalCandidateItems.map(item => item.model);
		const canonicalRecords = this.#modelRegistry.getCanonicalModels({
			availableOnly: false,
			candidates: candidateModels,
		});
		const canonicalModels = canonicalRecords
			.map(record => {
				const selectedModel = this.#modelRegistry.resolveCanonicalModel(record.id, {
					availableOnly: false,
					candidates: candidateModels,
				});
				if (!selectedModel) return undefined;
				const searchText = [
					record.id,
					record.name,
					selectedModel.provider,
					selectedModel.id,
					selectedModel.name,
					...record.variants.flatMap(variant => [variant.selector, variant.model.name]),
				].join(" ");
				return {
					kind: "canonical" as const,
					id: record.id,
					model: selectedModel,
					selector: record.id,
					variantCount: record.variants.length,
					searchText,
					normalizedSearchText: normalizeSearchText(searchText),
					compactSearchText: compactSearchText(searchText),
					availability: modelsBySelector.get(`${selectedModel.provider}/${selectedModel.id}`)?.availability ?? {
						status: "ready",
					},
				};
			})
			.filter((item): item is CanonicalModelItem => item !== undefined);

		this.#sortModels(models);
		this.#sortCanonicalModels(canonicalModels);

		this.#allModels = models;
		this.#filteredModels = models;
		this.#canonicalModels = canonicalModels;
		this.#filteredCanonicalModels = canonicalModels;
		this.#selectedIndex = Math.min(this.#selectedIndex, Math.max(0, models.length - 1));
	}

	#buildProviderTabs(): void {
		const activeTabId = this.#getActiveTab().id;
		const providerSet = new Set<string>();
		for (const item of this.#allModels) {
			providerSet.add(item.provider);
		}
		for (const provider of this.#modelRegistry.getDiscoverableProviders()) {
			const discoveryState = this.#modelRegistry.getProviderDiscoveryState(provider);
			if ((discoveryState?.models.length ?? 0) > 0) providerSet.add(provider);
		}
		const sortedProviderIds = Array.from(providerSet).sort((left, right) =>
			formatProviderTabLabel(left).localeCompare(formatProviderTabLabel(right)),
		);
		this.#providers = [...STATIC_PROVIDER_TABS, ...sortedProviderIds.map(createProviderTab)];
		const activeIndex = this.#providers.findIndex(tab => tab.id === activeTabId);
		this.#activeTabIndex =
			activeIndex >= 0 ? activeIndex : Math.min(this.#activeTabIndex, this.#providers.length - 1);
	}

	async #refreshSelectedProvider(): Promise<void> {
		const providerId = this.#getActiveProviderId();
		if (this.#scopedModels.length > 0 || !providerId) {
			return;
		}
		await this.#modelRegistry.refreshProvider(providerId);
		await this.#loadModels();
		this.#buildProviderTabs();
		this.#updateTabBar();
		this.#applyTabFilter();
		this.#tui.requestRender();
	}

	#updateTabBar(): void {
		this.#headerContainer.clear();

		const tabs: Tab[] = this.#providers.map(provider => ({ id: provider.id, label: provider.label }));
		const tabBar = new TabBar("Models", tabs, getTabBarTheme(), this.#activeTabIndex);
		tabBar.onTabChange = (_tab, index) => {
			this.#activeTabIndex = index;
			this.#selectedIndex = 0;
			this.#applyTabFilter();
			void this.#refreshSelectedProvider().catch(error => {
				this.#errorMessage = error instanceof Error ? error.message : String(error);
				this.#updateList();
				this.#tui.requestRender();
			});
		};
		this.#tabBar = tabBar;
		this.#headerContainer.addChild(tabBar);
	}

	#getActiveTab(): ProviderTabState {
		return this.#providers[this.#activeTabIndex] ?? STATIC_PROVIDER_TABS[0]!;
	}

	#getActiveTabId(): string {
		return this.#getActiveTab().id;
	}

	#getActiveProviderId(): string | undefined {
		return this.#getActiveTab().providerId;
	}

	#isCanonicalTab(): boolean {
		return this.#getActiveTabId() === CANONICAL_TAB;
	}

	#isGlobalSearchActive(): boolean {
		return this.#searchInput.getValue().trim().length > 0;
	}

	#filterModels(query: string): void {
		const activeProviderId = this.#getActiveProviderId();
		const trimmedQuery = query.trim();
		const hasQuery = trimmedQuery.length > 0;
		const includeSetupCatalog = activeProviderId !== undefined || trimmedQuery.length >= 2;

		let baseModels = includeSetupCatalog
			? this.#allModels
			: this.#allModels.filter(m => m.availability.status === "ready");
		const baseCanonicalModels =
			this.#isCanonicalTab() && !hasQuery
				? this.#canonicalModels.filter(m => m.availability.status === "ready")
				: this.#canonicalModels;

		if (activeProviderId && !hasQuery) {
			baseModels = this.#allModels.filter(m => m.provider === activeProviderId);
		}

		if (hasQuery) {
			const normalizedQuery = normalizeSearchText(query);
			const compactQuery = compactSearchText(query);
			const queryTokens = normalizedQuery.split(/\s+/).filter(token => token.length > 0);
			const substringMatches = baseModels.filter(item => {
				const searchText = getModelSearchText(item);
				const normalized = normalizeSearchText(searchText);
				const compact = compactSearchText(searchText);
				return (
					(queryTokens.length === 0 || queryTokens.every(token => normalized.includes(token))) &&
					(compactQuery.length === 0 || compact.includes(compactQuery))
				);
			});
			const matches =
				substringMatches.length > 0
					? substringMatches
					: fuzzyFilter(baseModels, query, item => getModelSearchText(item));
			this.#sortSearchModels(matches, query);
			this.#filteredModels = matches;
		} else {
			this.#filteredModels = baseModels;
			this.#filteredCanonicalModels = baseCanonicalModels;
		}

		const visibleCount =
			hasQuery || !this.#isCanonicalTab() ? this.#filteredModels.length : this.#filteredCanonicalModels.length;
		this.#selectedIndex = Math.min(this.#selectedIndex, Math.max(0, visibleCount - 1));
		this.#updateList();
	}

	#applyTabFilter(): void {
		const query = this.#searchInput.getValue();
		this.#filterModels(query);
	}

	#formatDiscoveryAge(fetchedAt: number | undefined): string | undefined {
		if (!fetchedAt) {
			return undefined;
		}
		const ageMs = Math.max(0, Date.now() - fetchedAt);
		if (ageMs < 60_000) {
			return "less than a minute ago";
		}
		const ageMinutes = Math.round(ageMs / 60_000);
		return `${ageMinutes}m ago`;
	}

	#formatDiscoveryErrorHint(error: string | undefined): string | undefined {
		if (!error) {
			return undefined;
		}
		const httpMatch = error.match(/^HTTP (\d+) from (.+)$/);
		if (!httpMatch) {
			return undefined;
		}
		const [, statusCode, url] = httpMatch;
		if (statusCode === "404") {
			return `  Discovery endpoint ${url} returned 404. Point baseUrl at the host that serves /models (usually .../v1).`;
		}
		return `  Discovery failed: ${error}`;
	}

	#getProviderEmptyStateMessage(): string | undefined {
		const activeProviderId = this.#getActiveProviderId();
		if (!activeProviderId || this.#searchInput.getValue().trim()) {
			return undefined;
		}
		const state = this.#modelRegistry.getProviderDiscoveryState(activeProviderId);
		if (!state) {
			return undefined;
		}
		const age = this.#formatDiscoveryAge(state.fetchedAt);
		switch (state.status) {
			case "cached":
				return age
					? `  Using cached model list from ${age}. Live refresh is still pending.`
					: "  Using cached model list. Live refresh is still pending.";
			case "unavailable":
				return (
					this.#formatDiscoveryErrorHint(state.error) ??
					(age ? `  Provider unavailable. Using cached model list from ${age}.` : "  Provider unavailable.")
				);
			case "unauthenticated":
				return "  Provider requires authentication before discovery. Use /provider login or /login for OAuth/subscription providers, or /provider add for API-compatible providers.";
			case "idle":
				return "  Provider has not been refreshed yet.";
			case "empty":
				return "  Discovery succeeded but returned 0 models. Check that /models returns { data: [{ id }] }.";
			case "ok":
				return undefined;
		}
	}

	#updateList(): void {
		this.#listContainer.clear();
		const isGlobalSearch = this.#isGlobalSearchActive();
		const isCanonicalTab = this.#isCanonicalTab() && !isGlobalSearch;
		const visibleItems = isCanonicalTab ? this.#filteredCanonicalModels : this.#filteredModels;

		const maxVisible = 10;
		const startIndex = Math.max(
			0,
			Math.min(this.#selectedIndex - Math.floor(maxVisible / 2), visibleItems.length - maxVisible),
		);
		const endIndex = Math.min(startIndex + maxVisible, visibleItems.length);

		const showProvider = isGlobalSearch || this.#getActiveProviderId() !== undefined;

		// Show visible slice of filtered models
		for (let i = startIndex; i < endIndex; i++) {
			const item = visibleItems[i];
			if (!item) continue;
			const canonicalItem = isCanonicalTab ? (item as CanonicalModelItem) : undefined;
			const providerItem = isCanonicalTab ? undefined : (item as ModelItem);

			const isSelected = i === this.#selectedIndex;

			// Build role badges (inverted: color as background, black text)
			const roleBadgeTokens: string[] = [];
			const defaultRoleInfo = getRoleInfo("default", this.#settings);
			const defaultAssigned = this.#roles.default;
			if (defaultRoleInfo.tag && defaultAssigned && modelsAreEqual(defaultAssigned.model, item.model)) {
				const badge = makeInvertedBadge(defaultRoleInfo.tag, defaultRoleInfo.color ?? "success");
				const thinkingLabel = getThinkingLevelMetadata(defaultAssigned.thinkingLevel).label;
				roleBadgeTokens.push(`${badge} ${theme.fg("dim", `(${thinkingLabel})`)}`);
			}
			const badgeText = roleBadgeTokens.length > 0 ? ` ${roleBadgeTokens.join(" ")}` : "";
			const availabilityText =
				item.availability.status === "ready" ? "" : theme.fg("warning", `  · ${item.availability.reason}`);
			const itemSuffix = `${badgeText}${availabilityText}`;

			let line = "";
			if (isSelected) {
				const prefix = theme.fg("accent", `${theme.nav.cursor} `);
				if (isCanonicalTab) {
					const variants = theme.fg("dim", ` [${canonicalItem?.variantCount ?? 0}]`);
					const backing = theme.fg("dim", ` -> ${item.model.provider}/${item.model.id}`);
					line = `${prefix}${theme.fg("accent", item.id)}${variants}${backing}${itemSuffix}`;
				} else if (showProvider) {
					const providerPrefix = theme.fg("dim", `${providerItem?.provider ?? ""}/`);
					line = `${prefix}${providerPrefix}${theme.fg("accent", providerItem?.id ?? item.id)}${itemSuffix}`;
				} else {
					line = `${prefix}${theme.fg("accent", item.id)}${itemSuffix}`;
				}
			} else {
				const prefix = "  ";
				if (isCanonicalTab) {
					const variants = theme.fg("dim", ` [${canonicalItem?.variantCount ?? 0}]`);
					const backing = theme.fg("dim", ` -> ${item.model.provider}/${item.model.id}`);
					line = `${prefix}${item.id}${variants}${backing}${itemSuffix}`;
				} else if (showProvider) {
					const providerPrefix = theme.fg("dim", `${providerItem?.provider ?? ""}/`);
					line = `${prefix}${providerPrefix}${providerItem?.id ?? item.id}${itemSuffix}`;
				} else {
					line = `${prefix}${item.id}${itemSuffix}`;
				}
			}

			this.#listContainer.addChild(new Text(line, 0, 0));
		}

		// Add scroll indicator if needed
		if (startIndex > 0 || endIndex < visibleItems.length) {
			const scrollInfo = theme.fg("muted", `  (${this.#selectedIndex + 1}/${visibleItems.length})`);
			this.#listContainer.addChild(new Text(scrollInfo, 0, 0));
		}

		// Show error message or "no results" if empty
		if (this.#errorMessage) {
			const errorLines = String(this.#errorMessage).split("\n");
			for (const line of errorLines) {
				this.#listContainer.addChild(new Text(theme.fg("error", line), 0, 0));
			}
		} else if (visibleItems.length === 0) {
			const statusMessage = this.#getProviderEmptyStateMessage();
			this.#listContainer.addChild(
				new Text(
					theme.fg("muted", statusMessage ?? "  No matching models. Try another search or provider tab."),
					0,
					0,
				),
			);
		} else {
			const selected = visibleItems[this.#selectedIndex];
			if (!selected) {
				return;
			}
			this.#listContainer.addChild(new Spacer(1));
			const suffix = isCanonicalTab
				? ` (${selected.model.provider}/${selected.model.id}, ${(selected as CanonicalModelItem).variantCount} variants)`
				: "";
			this.#listContainer.addChild(
				new Text(theme.fg("muted", `  Model Name: ${selected.model.name}${suffix}`), 0, 0),
			);
			if (selected.availability.status !== "ready" && selected.availability.action) {
				this.#listContainer.addChild(new Text(theme.fg("warning", `  ${selected.availability.action}`), 0, 0));
			}
		}
	}
	#getCurrentRoleThinkingLevel(role: string): ThinkingLevel {
		return this.#roles[role]?.thinkingLevel ?? ThinkingLevel.Inherit;
	}

	#getSelectedItem(): ModelItem | CanonicalModelItem | undefined {
		return this.#isCanonicalTab() && !this.#isGlobalSearchActive()
			? this.#filteredCanonicalModels[this.#selectedIndex]
			: this.#filteredModels[this.#selectedIndex];
	}

	handleInput(keyData: string): void {
		// Tab bar navigation
		if (this.#tabBar?.handleInput(keyData)) {
			return;
		}

		// Up arrow - navigate list (wrap to bottom when at top)
		if (matchesKey(keyData, "up")) {
			const itemCount =
				this.#isCanonicalTab() && !this.#isGlobalSearchActive()
					? this.#filteredCanonicalModels.length
					: this.#filteredModels.length;
			if (itemCount === 0) return;
			this.#selectedIndex = this.#selectedIndex === 0 ? itemCount - 1 : this.#selectedIndex - 1;
			this.#updateList();
			return;
		}

		// Down arrow - navigate list (wrap to top when at bottom)
		if (matchesKey(keyData, "down")) {
			const itemCount =
				this.#isCanonicalTab() && !this.#isGlobalSearchActive()
					? this.#filteredCanonicalModels.length
					: this.#filteredModels.length;
			if (itemCount === 0) return;
			this.#selectedIndex = this.#selectedIndex === itemCount - 1 ? 0 : this.#selectedIndex + 1;
			this.#updateList();
			return;
		}

		// Enter - select highlighted model directly. Canonical setup exposes one default model,
		// while temporary-only mode keeps the existing non-persistent quick-switch behavior.
		if (matchesKey(keyData, "enter") || matchesKey(keyData, "return") || keyData === "\n") {
			const selectedItem = this.#getSelectedItem();
			if (selectedItem) {
				this.#handleSelect(selectedItem, this.#temporaryOnly ? null : "default");
			}
			return;
		}

		// Escape or Ctrl+C - close selector
		if (getKeybindings().matches(keyData, "tui.select.cancel")) {
			this.#onCancelCallback();
			return;
		}

		// Pass everything else to search input
		this.#searchInput.handleInput(keyData);
		this.#filterModels(this.#searchInput.getValue());
	}
	#handleSelect(item: ModelItem | CanonicalModelItem, role: "default" | null, thinkingLevel?: ThinkingLevel): void {
		if (item.availability.status !== "ready") {
			if (item.availability.setup?.kind === "oauth_login" && this.#onLoginProviderCallback) {
				void this.#onLoginProviderCallback(item.availability.setup.provider).then(success => {
					if (success)
						void this.#loadModels().then(() => {
							this.#buildProviderTabs();
							this.#updateTabBar();
							this.#applyTabFilter();
							this.#tui.requestRender();
						});
				});
				return;
			}
			this.#errorMessage = item.availability.action ?? item.availability.reason;
			this.#updateList();
			this.#tui.requestRender();
			return;
		}

		// For temporary role, don't save to settings - just notify caller
		if (role === null) {
			this.#onSelectCallback(item.model, null, undefined, item.selector);
			return;
		}

		const selectedThinkingLevel = thinkingLevel ?? this.#getCurrentRoleThinkingLevel(role);

		// Update local state for UI
		this.#roles[role] = { model: item.model, thinkingLevel: selectedThinkingLevel };

		// Notify caller (for updating agent state if needed)
		this.#onSelectCallback(item.model, role, selectedThinkingLevel, item.selector);

		// Update list to show new badges
		this.#updateList();
	}

	getSearchInput(): Input {
		return this.#searchInput;
	}
}

/** Extract the first version number from a model ID (e.g. "gemini-2.5-pro" → 2.5, "Anthropic model-sonnet-4-6" → 4.6). */
function extractVersionNumber(id: string): number {
	// Dot-separated version: "gemini-2.5-pro" → 2.5
	const dotMatch = id.match(/(?:^|[-_])(\d+\.\d+)/);
	if (dotMatch) return Number.parseFloat(dotMatch[1]);
	// Dash-separated short segments: "Anthropic model-sonnet-4-6" → 4.6, "llama-3-1-8b" → 3.1
	const dashMatch = id.match(/(?:^|[-_])(\d{1,2})-(\d{1,2})(?=-|$)/);
	if (dashMatch) return Number.parseFloat(`${dashMatch[1]}.${dashMatch[2]}`);
	// Single number after separator: "gpt-4o" → 4
	const singleMatch = id.match(/(?:^|[-_])(\d+)/);
	if (singleMatch) return Number.parseFloat(singleMatch[1]);
	return 0;
}
