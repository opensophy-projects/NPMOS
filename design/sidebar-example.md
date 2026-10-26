<script lang="ts">
	import { page } from '$app/state';
	import { slide } from 'svelte/transition';
	import { brandingConfig } from '$lib/config/branding';
	import { contentUiDefaults, type SectionUiConfig } from '$lib/config/content-ui';
	import { siteConfig } from '$lib/config/site';
	import { cn } from '$lib/utils/cn';
	import ScrollArea from '$lib/components/ui-registry/ScrollArea.svelte';
	import Dropdown from '$lib/components/ui-registry/Dropdown.svelte';
	import ThemeToggle from '$lib/components/ui-registry/ThemeToggle.svelte';
	import SearchTrigger from '$lib/components/content/search/SearchTrigger.svelte';
	import Logo from '$lib/components/ui-registry/Logo.svelte';
	import ChevronRight from 'carbon-icons-svelte/lib/ChevronRight.svelte';
	import LogoGithub from 'carbon-icons-svelte/lib/LogoGithub.svelte';
	import { getHref } from '$lib/content/manifest';
	import type { ContentItem, ContentSectionLink } from '$lib/config/navigation';
	import { resolve } from '$app/paths';

	const {
		navigation,
		navigationLabel = contentUiDefaults.sidebar.navigationLabel,
		basePath = '/docs',
		showSearch = contentUiDefaults.search.enabled,
		showThemeToggle = contentUiDefaults.sidebar.showThemeToggle,
		showRepositoryLink = contentUiDefaults.sidebar.showRepositoryLink,
		repositoryUrl = siteConfig.links.github,
		repositoryAriaLabel = contentUiDefaults.sidebar.repositoryAriaLabel,
		searchConfig = contentUiDefaults.search,
		sectionLinks = [],
		showBranding = true
	}: {
		navigation: ContentItem[];
		navigationLabel?: string;
		basePath?: string;
		showSearch?: boolean;
		showThemeToggle?: boolean;
		showRepositoryLink?: boolean;
		repositoryUrl?: string;
		repositoryAriaLabel?: string;
		searchConfig?: SectionUiConfig['search'];
		sectionLinks?: ContentSectionLink[];
		showBranding?: boolean;
	} = $props();

	const currentPath = $derived(
		page.url.pathname.length > 1 ? page.url.pathname.replace(/\/+$/, '') : page.url.pathname
	);
	const currentHash = $derived(page.url.hash);

	let expandedGroups = $state<Partial<Record<string, boolean>>>({});
	let navElement = $state<HTMLElement | null>(null);
	let hoverIndicatorTop = $state(0);
	let hoverIndicatorHeight = $state(0);
	let hoverIndicatorVisible = $state(false);
	let hoveredElement: HTMLElement | null = null;
	let activeIndicatorLeft = $state(0);
	let activeIndicatorTop = $state(0);
	let activeIndicatorHeight = $state(0);
	let activeIndicatorVisible = $state(false);
	let activeIndicatorFollowsLayout = $state(false);
	let activeChildElement: HTMLElement | null = null;
	let pendingHoverRestoreFrame: number | null = null;
	let pendingActiveIndicatorFrame: number | null = null;
	let activeIndicatorFollowFrame: number | null = null;
	let activeIndicatorRevealFrame: number | null = null;
	let lastAutoExpandedPath = '';

	function normalizePath(pathname: string) {
		return pathname.length > 1 ? pathname.replace(/\/+$/, '') : pathname;
	}

	const dropdownItems = $derived(
		[
			{
				label: 'Главная',
				value: '/',
				href: '/'
			},
			...sectionLinks.map((link) => ({
				label: link.label,
				value: link.href,
				href: link.href,
				icon: link.icon,
				description: link.description
			}))
		].map((item) => {
			const normalizedHref = normalizePath(item.value);
			const isActive =
				currentPath === normalizedHref ||
				(normalizedHref !== '/' && currentPath.startsWith(`${normalizedHref}/`));
			return {
				...item,
				href: isActive ? undefined : item.href,
				active: isActive
			};
		})
	);

	function handleSectionClick() {
		// Navigation is handled natively by the <a> element's resolve()'d href.
		// This callback exists so Dropdown can close the menu after click.
	}

	function contentHref(slug: string) {
		return getHref(basePath, slug);
	}

	function itemMatchesCurrentPath(item: ContentItem): boolean {
		if (contentHref(item.slug) === currentPath) {
			return true;
		}
		return item.items?.some((child) => itemMatchesCurrentPath(child)) ?? false;
	}

	function findItemBySlug(items: ContentItem[], slug: string): ContentItem | undefined {
		for (const item of items) {
			if (item.slug === slug) return item;
			if (item.items) {
				const found = findItemBySlug(item.items, slug);
				if (found) return found;
			}
		}
		return undefined;
	}

	function isGroupActive(slug: string) {
		const explicit = expandedGroups[slug];
		if (explicit !== undefined) return explicit;
		return (
			findItemBySlug(navigation, slug)?.items?.some((child) => itemMatchesCurrentPath(child)) ??
			false
		);
	}

	function toggleGroup(slug: string) {
		expandedGroups[slug] = !isGroupActive(slug);
		followActiveIndicatorLayoutShift();
	}

	function autoExpandParentGroups(items: ContentItem[], parentSlugs: string[] = []) {
		for (const item of items) {
			if (item.items?.length) {
				const childSlugs = [...parentSlugs, item.slug];
				if (item.items.some((child) => itemMatchesCurrentPath(child))) {
					for (const slug of childSlugs) {
						if (expandedGroups[slug] !== true) {
							expandedGroups[slug] = true;
						}
					}
				}
				autoExpandParentGroups(item.items, childSlugs);
			}
		}
	}

	const getGroupSlideDuration = (node: Element) => {
		const height = Math.max(0, node.scrollHeight);
		return Math.min(420, Math.max(160, height / 1.2));
	};
	const groupSlide = (node: Element) => slide(node, { duration: getGroupSlideDuration(node) });

	function showHoverIndicator(node: HTMLElement) {
		if (!navElement) return;

		hoveredElement = node;
		const navRect = navElement.getBoundingClientRect();
		const nodeRect = node.getBoundingClientRect();

		hoverIndicatorTop = nodeRect.top - navRect.top;
		hoverIndicatorHeight = nodeRect.height;
		hoverIndicatorVisible = true;
	}

	function hideHoverIndicator() {
		hoveredElement = null;
		hoverIndicatorVisible = false;
	}

	function restoreHoverIndicator() {
		if (typeof document === 'undefined' || !navElement) return;

		const focusedElement =
			document.activeElement instanceof HTMLElement && navElement.contains(document.activeElement)
				? document.activeElement
				: null;
		const hoveredTarget =
			hoveredElement?.isConnected &&
			navElement.contains(hoveredElement) &&
			hoveredElement.matches(':hover')
				? hoveredElement
				: Array.from(navElement.querySelectorAll<HTMLElement>('a[href], button')).find((node) =>
						node.matches(':hover')
					);
		const target = hoveredTarget ?? focusedElement;

		if (target) {
			showHoverIndicator(target);
		}
	}

	function scheduleHoverIndicatorRestore() {
		if (typeof window === 'undefined') {
			restoreHoverIndicator();
			return;
		}

		if (pendingHoverRestoreFrame !== null) {
			window.cancelAnimationFrame(pendingHoverRestoreFrame);
		}

		pendingHoverRestoreFrame = window.requestAnimationFrame(() => {
			pendingHoverRestoreFrame = null;
			restoreHoverIndicator();
		});
	}

	function handleNavFocusOut(event: FocusEvent) {
		if (!navElement) return;
		if (event.relatedTarget instanceof Node && navElement.contains(event.relatedTarget)) return;
		hideHoverIndicator();
	}

	function updateActiveIndicator() {
		if (!navElement || !activeChildElement) {
			activeIndicatorVisible = false;
			return;
		}

		const navRect = navElement.getBoundingClientRect();
		const nodeRect = activeChildElement.getBoundingClientRect();
		const groupPanel = activeChildElement.closest('[data-sidebar-group-panel]');
		const clipRect =
			groupPanel instanceof HTMLElement ? groupPanel.getBoundingClientRect() : nodeRect;
		const visibleTop = Math.max(nodeRect.top, clipRect.top);
		const visibleBottom = Math.min(nodeRect.bottom, clipRect.bottom);
		const visibleHeight = Math.max(0, visibleBottom - visibleTop);

		activeIndicatorLeft = nodeRect.left - navRect.left - 8;
		activeIndicatorTop = visibleTop - navRect.top;
		activeIndicatorHeight = visibleHeight;
		activeIndicatorVisible = visibleHeight > 0;
	}

	function scheduleActiveIndicatorUpdate() {
		if (typeof window === 'undefined') {
			updateActiveIndicator();
			return;
		}

		if (pendingActiveIndicatorFrame !== null) {
			window.cancelAnimationFrame(pendingActiveIndicatorFrame);
		}

		pendingActiveIndicatorFrame = window.requestAnimationFrame(() => {
			pendingActiveIndicatorFrame = null;
			updateActiveIndicator();
		});
	}

	function followActiveIndicatorLayoutShift() {
		if (typeof window === 'undefined') {
			updateActiveIndicator();
			return;
		}

		if (activeIndicatorFollowFrame !== null) {
			window.cancelAnimationFrame(activeIndicatorFollowFrame);
		}

		activeIndicatorFollowsLayout = true;
		const startedAt = window.performance.now();
		const duration = 460;

		const follow = (now: number) => {
			updateActiveIndicator();

			if (now - startedAt < duration) {
				activeIndicatorFollowFrame = window.requestAnimationFrame(follow);
				return;
			}

			activeIndicatorFollowFrame = null;
			activeIndicatorFollowsLayout = false;
			scheduleActiveIndicatorUpdate();
		};

		activeIndicatorFollowFrame = window.requestAnimationFrame(follow);
	}

	function revealActiveIndicatorWithoutMotion() {
		if (typeof window === 'undefined') {
			updateActiveIndicator();
			return;
		}

		if (activeIndicatorFollowFrame !== null) {
			scheduleActiveIndicatorUpdate();
			return;
		}

		if (activeIndicatorRevealFrame !== null) {
			window.cancelAnimationFrame(activeIndicatorRevealFrame);
		}

		activeIndicatorFollowsLayout = true;
		updateActiveIndicator();

		activeIndicatorRevealFrame = window.requestAnimationFrame(() => {
			activeIndicatorRevealFrame = window.requestAnimationFrame(() => {
				activeIndicatorRevealFrame = null;
				if (activeIndicatorFollowFrame === null) {
					activeIndicatorFollowsLayout = false;
				}
			});
		});
	}

	function activateChildIndicator(node: HTMLElement) {
		const shouldRevealWithoutMotion = !activeIndicatorVisible;
		activeChildElement = node;

		if (shouldRevealWithoutMotion) {
			revealActiveIndicatorWithoutMotion();
			return;
		}

		if (typeof window !== 'undefined' && activeIndicatorRevealFrame !== null) {
			window.cancelAnimationFrame(activeIndicatorRevealFrame);
			activeIndicatorRevealFrame = null;
			if (activeIndicatorFollowFrame === null) {
				activeIndicatorFollowsLayout = false;
			}
		}

		scheduleActiveIndicatorUpdate();
	}

	function registerActiveChild(node: HTMLElement, isActive: boolean) {
		if (isActive) {
			activateChildIndicator(node);
		}

		return {
			update(nextIsActive: boolean) {
				if (nextIsActive) {
					activateChildIndicator(node);
				} else if (activeChildElement === node) {
					activeChildElement = null;
					scheduleActiveIndicatorUpdate();
				}
			},
			destroy() {
				if (activeChildElement === node) {
					activeChildElement = null;
					scheduleActiveIndicatorUpdate();
				}
			}
		};
	}

	$effect(() => {
		const path = currentPath;

		if (lastAutoExpandedPath === path) return;

		autoExpandParentGroups(navigation);
		followActiveIndicatorLayoutShift();

		lastAutoExpandedPath = path;
	});

	$effect(() => {
		if (currentPath || currentHash) {
			updateActiveIndicator();
			scheduleHoverIndicatorRestore();
			scheduleActiveIndicatorUpdate();
		}

		if (typeof window === 'undefined') return;

		window.addEventListener('resize', scheduleActiveIndicatorUpdate);

		return () => {
			window.removeEventListener('resize', scheduleActiveIndicatorUpdate);
			if (pendingActiveIndicatorFrame !== null) {
				window.cancelAnimationFrame(pendingActiveIndicatorFrame);
				pendingActiveIndicatorFrame = null;
			}
			if (pendingHoverRestoreFrame !== null) {
				window.cancelAnimationFrame(pendingHoverRestoreFrame);
				pendingHoverRestoreFrame = null;
			}
			if (activeIndicatorFollowFrame !== null) {
				window.cancelAnimationFrame(activeIndicatorFollowFrame);
				activeIndicatorFollowFrame = null;
				activeIndicatorFollowsLayout = false;
			}
		};
	});
</script>

<aside class="flex h-full min-h-0 flex-col bg-background" aria-label={navigationLabel + ' sidebar'}>
	{#if showBranding}
		<a href={resolve('/')} class="mb-4 flex items-center gap-2 p-4 pb-0 lg:p-0">
			<span class="inline-flex shrink-0 items-center" aria-hidden="true">
				<Logo size={14} />
			</span>
			<span class="text-xl font-medium tracking-tight text-foreground lowercase"
				>{brandingConfig.name}</span
			>
		</a>
	{/if}

	<div class="grid gap-2 p-4 lg:px-0">
		<Dropdown items={dropdownItems} onItemClick={handleSectionClick} class="w-full"></Dropdown>

		{#if showSearch}
			<SearchTrigger {searchConfig} />
		{/if}
	</div>

	<ScrollArea
		class="flex-1"
		viewportClass="px-4 py-4 lg:px-0 min-h-0"
		viewportStyle="mask-image: linear-gradient(to bottom, transparent, black 16px, black calc(100% - 16px), transparent); -webkit-mask-image: linear-gradient(to bottom, transparent, black 16px, black calc(100% - 16px), transparent);"
	>
		<nav
			class="sidebar-nav relative flex flex-col gap-1"
			class:sidebar-nav-layout-shift={activeIndicatorFollowsLayout}
			aria-label={navigationLabel}
			bind:this={navElement}
			onmouseleave={hideHoverIndicator}
			onfocusout={handleNavFocusOut}
			style={`
				--sidebar-hover-top: ${hoverIndicatorTop.toString()}px;
				--sidebar-hover-height: ${hoverIndicatorHeight.toString()}px;
				--sidebar-hover-opacity: ${hoverIndicatorVisible ? '1' : '0'};
				--sidebar-active-left: ${activeIndicatorLeft.toString()}px;
				--sidebar-active-top: ${activeIndicatorTop.toString()}px;
				--sidebar-active-height: ${activeIndicatorHeight.toString()}px;
				--sidebar-active-opacity: ${activeIndicatorVisible ? '1' : '0'};
			`}
		>
			{#each navigation as item (item.slug)}
				<!-- eslint-disable-next-line @typescript-eslint/no-confusing-void-expression -->
				{@render renderNavItem(item, 0)}
			{/each}
		</nav>
	</ScrollArea>

	<div class="flex items-center gap-1 p-4 lg:p-0">
		{#if showThemeToggle}
			<ThemeToggle />
		{/if}
		{#if showRepositoryLink}
			<a
				class="group transition-scale inset-shadow relative inline-flex size-7 cursor-pointer items-center justify-center rounded-sm bg-background-inset text-foreground duration-150 ease-out active:scale-[0.95]"
				href={repositoryUrl}
				target="_blank"
				rel="external"
				aria-label={`${repositoryAriaLabel} (opens in a new tab)`}
			>
				<LogoGithub class="size-4 flex-none" />
			</a>
		{/if}
	</div>
</aside>

{#snippet renderNavItem(item: ContentItem, depth: number)}
	{#if item.items?.length}
		{@const groupIsActive = isGroupActive(item.slug)}
		<div class="flex flex-col">
			<button
				onclick={() => { toggleGroup(item.slug); }}
				onmouseenter={(e) => { showHoverIndicator(e.currentTarget); }}
				onfocus={(e) => { showHoverIndicator(e.currentTarget); }}
				class={cn(
					'relative z-10 flex w-full items-center justify-between rounded-sm px-3 py-1.5 text-sm font-medium tracking-normal transition-colors duration-150 ease-out hover:text-foreground',
					groupIsActive ? 'text-foreground' : 'text-foreground-muted'
				)}
			>
				<span class="flex items-center gap-2">
					{item.name}
				</span>
				<ChevronRight
					class={cn('size-4 transition-transform duration-150', groupIsActive && 'rotate-90')}
				/>
			</button>
			{#if groupIsActive}
				<div data-sidebar-group-panel transition:groupSlide class="overflow-hidden">
					<div
						class={cn(
							'relative z-10 flex flex-col gap-0 before:absolute before:top-0 before:bottom-0 before:w-px before:bg-border',
							depth === 0 ? 'pl-5 before:left-3' : 'pl-4 before:left-2'
						)}
					>
						{#each item.items as child (child.slug)}
							<!-- eslint-disable-next-line @typescript-eslint/no-confusing-void-expression -->
							{@render renderNavItem(child, depth + 1)}
						{/each}
					</div>
				</div>
			{/if}
		</div>
	{:else}
		{@const href = contentHref(item.slug)}
		{@const isActive = currentPath === href}
		<a
			// @ts-expect-error arg cannot be cast as `resolve`s expected type
			href={resolve(href)}
			onmouseenter={(e) => { showHoverIndicator(e.currentTarget); }}
			onfocus={(e) => { showHoverIndicator(e.currentTarget); }}
			use:registerActiveChild={isActive}
			class={cn(
				'relative flex items-center gap-2 rounded-sm px-3 py-1.5 text-sm font-medium tracking-normal transition-colors duration-150 ease-out',
				isActive
					? 'sidebar-active-child text-accent'
					: 'text-foreground-muted hover:text-foreground'
			)}
		>
			{item.name}
		</a>
	{/if}
{/snippet}

<style>
	.sidebar-nav::before {
		content: '';
		position: absolute;
		inset-inline: 0px;
		top: 0;
		height: var(--sidebar-hover-height);
		border-radius: var(--radius-sm);
		background: var(--color-background-muted);
		opacity: var(--sidebar-hover-opacity);
		pointer-events: none;
		transform: translateY(var(--sidebar-hover-top));
		transition:
			transform 150ms ease-out,
			height 150ms ease-out,
			opacity 150ms ease-out;
		will-change: transform, height, opacity;
		z-index: 0;
	}

	.sidebar-nav::after {
		content: '';
		position: absolute;
		top: 0;
		left: 0;
		width: 1px;
		height: var(--sidebar-active-height);
		border-radius: 9999px;
		background-image: linear-gradient(
			to bottom,
			transparent,
			oklch(from var(--color-accent) l c h / 0.68) 18%,
			var(--color-accent) 50%,
			oklch(from var(--color-accent) l c h / 0.68) 82%,
			transparent
		);
		filter: drop-shadow(0 0 6px oklch(from var(--color-accent) l c h / 0.38));
		opacity: var(--sidebar-active-opacity);
		pointer-events: none;
		transform: translate(var(--sidebar-active-left), var(--sidebar-active-top));
		transition:
			transform 150ms ease-out,
			height 150ms ease-out,
			opacity 150ms ease-out;
		will-change: transform, height, opacity;
		z-index: 20;
	}

	.sidebar-nav-layout-shift::after {
		transition: opacity 150ms ease-out;
	}

	@media (max-width: 1023.98px) {
		.sidebar-nav::before {
			display: none;
		}
	}
</style>
