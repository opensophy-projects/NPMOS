package tuning

import (
	"fmt"
	"math"
	"regexp"
	"runtime"
	"strconv"

	"openappsec.io/log"
)

const minClusterSize = 2

type node struct {
	token     string
	count     int
	depth     int
	depths    map[int]bool
	depthsRev map[int]bool
	origin    map[string]bool
	tokens    []string
	children  map[string]*node
	parents   map[string]*node
}

func newURINode(token string) *node {
	return &node{token: token,
		origin:    map[string]bool{},
		depths:    map[int]bool{},
		depthsRev: map[int]bool{},
		children:  map[string]*node{},
		parents:   map[string]*node{}}
}

func (n *node) String() string {
	return fmt.Sprintf("token: %v, children: %v, parents: %v, depth: %v, count: %v",
		n.token, len(n.children), len(n.parents), n.depth, n.count)
}

type nodeID struct {
	token string
}

type tree struct {
	root     *node
	nodesMap map[nodeID]*node
	isParam  bool
}

func splitURI(uri string) []string {
	if uri[len(uri)-1] == '/' {
		uri = uri[:len(uri)-1]
	}
	alnumSplit := regexp.MustCompile("\\W+")
	hexRe := regexp.MustCompile("\\b[a-f0-9]{6,}\\b|\\b[A-F0-9]{6,}\\b")
	parts := alnumSplit.Split(uri, -1)
	for i, part := range parts {
		if _, err := strconv.Atoi(part); err == nil {
			parts[i] = "_num"
			continue
		}
		if hexRe.MatchString(part) {
			parts[i] = "_num"
			continue
		}

	}
	if parts[0] == "" {
		return parts[1:]
	}
	return parts
}

func newURITree(isParam bool) *tree {
	root := newURINode("/")
	rootNodeID := nodeID{
		token: "/",
	}
	return &tree{root: root, nodesMap: map[nodeID]*node{rootNodeID: root}, isParam: isParam}
}

func (t *tree) addURI(uri string) {
	parts := splitURI(uri)
	currentNode := t.root
	currentNode.origin[uri] = true
	currentNode.count++
	length := len(parts)
	for i, part := range parts {
		id := nodeID{
			token: part,
		}
		if _, ok := t.nodesMap[id]; !ok {
			t.nodesMap[id] = newURINode(part)
		}
		nextNode := t.nodesMap[id]
		nextNode.origin[uri] = true
		nextNode.count++
		nextNode.depths[i] = true
		nextNode.depthsRev[length-i-1] = true

		currentNode.children[part] = nextNode
		currentNode.children[part].parents[currentNode.token] = currentNode
		currentNode.children[part].depth = i + 1

		currentNode = nextNode
	}
}

func (t *tree) addURIs(uris []string) {
	for _, uri := range uris {
		t.addURI(uri)
	}
}

func (t *tree) addURIsFromNode(node *node) {
	for uri := range node.origin {
		t.addURI(uri)
	}
}

func min(intArr map[int]bool) int {
	minVal := math.MaxInt32
	for val := range intArr {
		if val < minVal {
			minVal = val
		}
	}
	return minVal
}

func maxDepth(intArr map[int]bool) int {
	maxVal := 0
	for val := range intArr {
		if val > maxVal {
			maxVal = val
		}
	}
	return maxVal
}

func (t *tree) getBestNode() *node {
	maxScore := -1.0
	var bestNode *node
	for _, n := range t.nodesMap {
		if n.token == "/" || n.token == "_num" {
			continue
		}
		n.tokens = createPattern(n)
		positionFactor := float64(len(n.depths))
		if float64(len(n.depthsRev)) < positionFactor {
			positionFactor = float64(len(n.depthsRev))
		}
		positionFactor = math.Sqrt(float64(min(n.depths)+1)) / positionFactor
		lastTokenFactor := 0

		if t.isParam && len(n.depthsRev) == 1 && n.depthsRev[0] {
			lastTokenFactor = maxDepth(n.depths)
		}

		score := float64(len(n.origin)-1) * math.Log2(float64(len(n.tokens)+lastTokenFactor)) * positionFactor
		if score > maxScore {
			maxScore = score
			bestNode = n
		}
	}
	if maxScore == 0 {
		for _, n := range t.nodesMap {
			if n.token == "" || n.token == "_num" {
				continue
			}

			score := float64(len(n.origin)-1) * math.Log2(float64(len(n.tokens)+1))

			if score > maxScore {
				maxScore = score
				bestNode = n
			}
		}
	}
	log.Infof("best node: %v, score: %v", bestNode, maxScore)
	return bestNode
}

func createPattern(bestNode *node) []string {
	pattern := []string{}
	subTree := newURITree(false)
	subTree.addURIsFromNode(bestNode)

	for _, n := range subTree.nodesMap {
		if len(n.origin) == len(subTree.root.origin) && n != subTree.root {
			pattern = append(pattern, n.token)
		}
	}
	return pattern
}

func collapseParams(params []string) ([][]string, []string) {
	return tokenizeCollapse(params, true)
}

func collapseUrls(urls []string) ([][]string, []string) {
	return tokenizeCollapse(urls, false)
}

func tokenizeCollapse(origins []string, isParam bool) ([][]string, []string) {
	patterns := make([][]string, 0)
	nonClustered := make([]string, 0)
	topTree := newURITree(isParam)
	topTree.addURIs(origins)
	for len(topTree.root.origin) > 0 {
		bestNode := topTree.getBestNode()
		if bestNode == nil {
			log.Warnf("best node is nil for origins: %v", origins)
			return patterns, nonClustered
		}
		if len(bestNode.origin) > minClusterSize {
			patterns = append(patterns, createPattern(bestNode))
		} else {
			for val := range bestNode.origin {
				nonClustered = append(nonClustered, val)
			}
		}
		for val := range bestNode.origin {
			delete(topTree.root.origin, val)
		}
		subTree := newURITree(isParam)
		subTree.addURIsFromNode(topTree.root)
		topTree = subTree
		runtime.Gosched()
	}
	return patterns, nonClustered
}
