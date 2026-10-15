import { useInfiniteQuery, type QueryKey } from "@tanstack/react-query";
import { LIST_PAGE } from "@/services/api";

/**
 * A list read a page at a time, newest first (checklist item 18).
 *
 * The next page is asked for by `offset` while pages come back full; a short
 * page is the end. The backend keeps every page full until the last one --
 * even for scoped analyses -- which is what makes that rule safe.
 *
 * `key` should start with the list's existing query key: invalidation matches
 * by prefix, so whatever refreshed the old one-page query refreshes this too.
 */
export function usePagedList<T>(key: QueryKey, fetchPage: (offset: number) => Promise<T[]>) {
  const query = useInfiniteQuery({
    queryKey: key,
    queryFn: ({ pageParam }) => fetchPage(pageParam),
    initialPageParam: 0,
    getNextPageParam: (last: T[], pages: T[][]) =>
      last.length < LIST_PAGE ? undefined : pages.length * LIST_PAGE,
  });
  return {
    data: query.data?.pages.flat(),
    isPending: query.isPending,
    isError: query.isError,
    error: query.error,
    refetch: query.refetch,
    hasMore: query.hasNextPage,
    loadMore: () => void query.fetchNextPage(),
    isLoadingMore: query.isFetchingNextPage,
  };
}
