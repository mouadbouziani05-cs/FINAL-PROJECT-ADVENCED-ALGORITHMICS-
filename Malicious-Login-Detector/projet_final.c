/*
 
 MALICIOUS LOGIN DETECTOR - VERSION COMPLETE
 Projet: Structures de Données et Algorithmes
 
 Modules Implémentés:
 1. Arrays et Linked Lists (Stockage)
 2. Stack (Détection utilisateurs suspects)
 3. Queue (Simulation de requêtes)
 4. Search (Recherche linéaire et binaire)
 5. Sort (4 algorithmes: Bubble, Insertion, Quick, Merge)
 6. BST (Classification par niveau de menace)
 7. Graph (Propagation d'attaques avec BFS/DFS)
 
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdbool.h>

/*  CONSTANTES  */
#define MAX_USERNAME 64
#define MAX_IP 32
#define MAX_TIMESTAMP 32
#define MAX_LINE 512
#define MAX_USERS 500
#define STACK_SIZE 10

/*  ENUMERATIONS  */
typedef enum {
    STATUS_SUCCESS = 1,
    STATUS_FAILURE = 0
} LoginStatus;

typedef enum {
    NORMAL,
    SUSPICIOUS,
    ATTACK
} ThreatLevel;

/*  STRUCTURES DE BASE  */

// Enregistrement d'une tentative de connexion
typedef struct {
    char timestamp[MAX_TIMESTAMP];
    char username[MAX_USERNAME];
    char ip[MAX_IP];
    LoginStatus status;
} LoginRecord;

/*  MODULE 1: LINKED LIST  */

typedef struct Node {
    LoginRecord data;
    struct Node* next;
} Node;

typedef struct {
    Node* head;
    Node* tail;
    int size;
} LinkedList;

// Créer une linked list
LinkedList* ll_create() {
    LinkedList* list = (LinkedList*)malloc(sizeof(LinkedList));
    list->head = list->tail = NULL;
    list->size = 0;
    return list;
}

// Insérer en queue - O(1)
void ll_insert_tail(LinkedList* list, LoginRecord record) {
    Node* new_node = (Node*)malloc(sizeof(Node));
    new_node->data = record;
    new_node->next = NULL;
    
    if (list->tail == NULL) {
        list->head = list->tail = new_node;
    } else {
        list->tail->next = new_node;
        list->tail = new_node;
    }
    list->size++;
}

// Détruire la liste
void ll_destroy(LinkedList* list) {
    Node* current = list->head;
    while (current) {
        Node* next = current->next;
        free(current);
        current = next;
    }
    free(list);
}

/*  MODULE 2: STACK  */

typedef struct StackNode {
    LoginStatus status;
    struct StackNode* next;
} StackNode;

typedef struct {
    StackNode* top;
    int size;
    int max_size;
} Stack;

// Créer une pile
Stack* stack_create(int max_size) {
    Stack* stack = (Stack*)malloc(sizeof(Stack));
    stack->top = NULL;
    stack->size = 0;
    stack->max_size = max_size;
    return stack;
}

// Push - O(1)
void stack_push(Stack* stack, LoginStatus status) {
    // Limiter la taille
    if (stack->size >= stack->max_size) {
        // Supprimer le fond
        if (stack->top) {
            StackNode* curr = stack->top;
            StackNode* prev = NULL;
            while (curr->next) {
                prev = curr;
                curr = curr->next;
            }
            if (prev) prev->next = NULL;
            free(curr);
            stack->size--;
        }
    }
    
    StackNode* new_node = (StackNode*)malloc(sizeof(StackNode));
    new_node->status = status;
    new_node->next = stack->top;
    stack->top = new_node;
    stack->size++;
}

// Compter les échecs consécutifs depuis le sommet - O(k)
int stack_count_consecutive_failures(Stack* stack) {
    int count = 0;
    StackNode* current = stack->top;
    
    while (current && current->status == STATUS_FAILURE) {
        count++;
        current = current->next;
    }
    return count;
}

void stack_destroy(Stack* stack) {
    StackNode* current = stack->top;
    while (current) {
        StackNode* next = current->next;
        free(current);
        current = next;
    }
    free(stack);
}

/*  MODULE 3: QUEUE  */

typedef struct QueueNode {
    LoginRecord data;
    int priority;
    struct QueueNode* next;
} QueueNode;

typedef struct {
    QueueNode* front;
    QueueNode* rear;
    int size;
} Queue;

Queue* queue_create() {
    Queue* queue = (Queue*)malloc(sizeof(Queue));
    queue->front = queue->rear = NULL;
    queue->size = 0;
    return queue;
}

// Enqueue avec priorité - O(n) pour priority queue
void queue_enqueue(Queue* queue, LoginRecord record, int priority) {
    QueueNode* new_node = (QueueNode*)malloc(sizeof(QueueNode));
    new_node->data = record;
    new_node->priority = priority;
    new_node->next = NULL;
    
    // Queue vide
    if (queue->rear == NULL) {
        queue->front = queue->rear = new_node;
    } 
    // Priority queue: insérer selon priorité
    else if (priority > 0) {
        // Haute priorité = traiter en premier
        if (priority > queue->front->priority) {
            new_node->next = queue->front;
            queue->front = new_node;
        } else {
            QueueNode* curr = queue->front;
            while (curr->next && curr->next->priority >= priority) {
                curr = curr->next;
            }
            new_node->next = curr->next;
            curr->next = new_node;
            if (new_node->next == NULL) {
                queue->rear = new_node;
            }
        }
    }
    // FIFO normal
    else {
        queue->rear->next = new_node;
        queue->rear = new_node;
    }
    
    queue->size++;
}

bool queue_is_empty(Queue* queue) {
    return queue->front == NULL;
}

void queue_destroy(Queue* queue) {
    QueueNode* current = queue->front;
    while (current) {
        QueueNode* next = current->next;
        free(current);
        current = next;
    }
    free(queue);
}

/*  STATISTIQUES UTILISATEUR  */

typedef struct {
    char username[MAX_USERNAME];
    int total_attempts;
    int failed_attempts;
    int consecutive_failures;
    ThreatLevel threat_level;
    Stack* history;
} UserStats;

UserStats users[MAX_USERS];
int userCount = 0;

int findUser(const char* username) {
    for (int i = 0; i < userCount; i++) {
        if (strcmp(users[i].username, username) == 0) {
            return i;
        }
    }
    return -1;
}

/*  MODULE 4: SEARCH  */

// Recherche linéaire - O(n)
bool linear_search(char** array, int size, const char* target) {
    for (int i = 0; i < size; i++) {
        if (strcmp(array[i], target) == 0) {
            return true;
        }
    }
    return false;
}

// Recherche binaire - O(log n) - tableau doit être trié
bool binary_search(char** sorted_array, int size, const char* target) {
    int left = 0, right = size - 1;
    
    while (left <= right) {
        int mid = left + (right - left) / 2;
        int cmp = strcmp(sorted_array[mid], target);
        
        if (cmp == 0) return true;
        else if (cmp < 0) left = mid + 1;
        else right = mid - 1;
    }
    return false;
}

/*  MODULE 5: SORT  */

void swap_users(UserStats* a, UserStats* b) {
    UserStats temp = *a;
    *a = *b;
    *b = temp;
}

// Bubble Sort - O(n²)
void bubble_sort(UserStats* array, int n) {
    for (int i = 0; i < n - 1; i++) {
        for (int j = 0; j < n - i - 1; j++) {
            if (array[j].failed_attempts < array[j + 1].failed_attempts) {
                swap_users(&array[j], &array[j + 1]);
            }
        }
    }
}

// Insertion Sort - O(n²)
void insertion_sort(UserStats* array, int n) {
    for (int i = 1; i < n; i++) {
        UserStats key = array[i];
        int j = i - 1;
        
        while (j >= 0 && array[j].failed_attempts < key.failed_attempts) {
            array[j + 1] = array[j];
            j--;
        }
        array[j + 1] = key;
    }
}

// Quick Sort - O(n log n) moyen
int partition(UserStats* array, int low, int high) {
    int pivot = array[high].failed_attempts;
    int i = low - 1;
    
    for (int j = low; j < high; j++) {
        if (array[j].failed_attempts >= pivot) {
            i++;
            swap_users(&array[i], &array[j]);
        }
    }
    swap_users(&array[i + 1], &array[high]);
    return i + 1;
}

void quick_sort_recursive(UserStats* array, int low, int high) {
    if (low < high) {
        int pi = partition(array, low, high);
        quick_sort_recursive(array, low, pi - 1);
        quick_sort_recursive(array, pi + 1, high);
    }
}

void quick_sort(UserStats* array, int n) {
    quick_sort_recursive(array, 0, n - 1);
}

// Merge Sort - O(n log n) garanti
void merge(UserStats* array, int left, int mid, int right) {
    int n1 = mid - left + 1;
    int n2 = right - mid;
    
    UserStats* L = (UserStats*)malloc(n1 * sizeof(UserStats));
    UserStats* R = (UserStats*)malloc(n2 * sizeof(UserStats));
    
    for (int i = 0; i < n1; i++) L[i] = array[left + i];
    for (int j = 0; j < n2; j++) R[j] = array[mid + 1 + j];
    
    int i = 0, j = 0, k = left;
    
    while (i < n1 && j < n2) {
        if (L[i].failed_attempts >= R[j].failed_attempts) {
            array[k++] = L[i++];
        } else {
            array[k++] = R[j++];
        }
    }
    
    while (i < n1) array[k++] = L[i++];
    while (j < n2) array[k++] = R[j++];
    
    free(L);
    free(R);
}

void merge_sort_recursive(UserStats* array, int left, int right) {
    if (left < right) {
        int mid = left + (right - left) / 2;
        merge_sort_recursive(array, left, mid);
        merge_sort_recursive(array, mid + 1, right);
        merge(array, left, mid, right);
    }
}

void merge_sort(UserStats* array, int n) {
    merge_sort_recursive(array, 0, n - 1);
}

/*  MODULE 6: BST  */

typedef struct TreeNode {
    char username[MAX_USERNAME];
    int failure_count;
    ThreatLevel threat_level;
    struct TreeNode* left;
    struct TreeNode* right;
} TreeNode;

ThreatLevel classify_threat(int failures) {
    if (failures >= 10) return ATTACK;
    if (failures >= 3) return SUSPICIOUS;
    return NORMAL;
}

TreeNode* bst_insert(TreeNode* root, const char* username, int failures) {
    if (root == NULL) {
        TreeNode* node = (TreeNode*)malloc(sizeof(TreeNode));
        strcpy(node->username, username);
        node->failure_count = failures;
        node->threat_level = classify_threat(failures);
        node->left = node->right = NULL;
        return node;
    }
    
    int cmp = strcmp(username, root->username);
    if (cmp < 0) {
        root->left = bst_insert(root->left, username, failures);
    } else if (cmp > 0) {
        root->right = bst_insert(root->right, username, failures);
    }
    
    return root;
}

void bst_inorder_by_level(TreeNode* root, ThreatLevel level) {
    if (root == NULL) return;
    
    bst_inorder_by_level(root->left, level);
    
    if (root->threat_level == level) {
        const char* level_str = (level == ATTACK) ? "ATTACK" :
                               (level == SUSPICIOUS) ? "SUSPICIOUS" : "NORMAL";
        printf("  [%s] %s - %d failures\n", level_str, root->username, root->failure_count);
    }
    
    bst_inorder_by_level(root->right, level);
}

void bst_destroy(TreeNode* root) {
    if (root) {
        bst_destroy(root->left);
        bst_destroy(root->right);
        free(root);
    }
}

/*  MODULE 7: GRAPH  */

typedef struct GraphEdge {
    int target_index;
    char shared_ip[MAX_IP];
    struct GraphEdge* next;
} GraphEdge;

typedef struct {
    char username[MAX_USERNAME];
    GraphEdge* edges;
    bool visited;
    int distance;
} GraphNode;

typedef struct {
    GraphNode* nodes;
    int num_nodes;
    int capacity;
} Graph;

Graph* graph_create(int capacity) {
    Graph* graph = (Graph*)malloc(sizeof(Graph));
    graph->nodes = (GraphNode*)malloc(capacity * sizeof(GraphNode));
    graph->num_nodes = 0;
    graph->capacity = capacity;
    return graph;
}

int graph_find_vertex(Graph* graph, const char* username) {
    for (int i = 0; i < graph->num_nodes; i++) {
        if (strcmp(graph->nodes[i].username, username) == 0) {
            return i;
        }
    }
    return -1;
}

void graph_add_vertex(Graph* graph, const char* username) {
    if (graph_find_vertex(graph, username) == -1 && 
        graph->num_nodes < graph->capacity) {
        strcpy(graph->nodes[graph->num_nodes].username, username);
        graph->nodes[graph->num_nodes].edges = NULL;
        graph->nodes[graph->num_nodes].visited = false;
        graph->num_nodes++;
    }
}

void graph_add_edge(Graph* graph, const char* from, const char* to, const char* ip) {
    int from_idx = graph_find_vertex(graph, from);
    int to_idx = graph_find_vertex(graph, to);
    
    if (from_idx != -1 && to_idx != -1) {
        GraphEdge* new_edge = (GraphEdge*)malloc(sizeof(GraphEdge));
        new_edge->target_index = to_idx;
        strcpy(new_edge->shared_ip, ip);
        new_edge->next = graph->nodes[from_idx].edges;
        graph->nodes[from_idx].edges = new_edge;
    }
}

// BFS - O(V + E)
void graph_bfs(Graph* graph, const char* start_username) {
    int start_idx = graph_find_vertex(graph, start_username);
    if (start_idx == -1) return;
    
    // Réinitialiser visited
    for (int i = 0; i < graph->num_nodes; i++) {
        graph->nodes[i].visited = false;
        graph->nodes[i].distance = -1;
    }
    
    // Queue pour BFS
    int* queue = (int*)malloc(graph->num_nodes * sizeof(int));
    int front = 0, rear = 0;
    
    graph->nodes[start_idx].visited = true;
    graph->nodes[start_idx].distance = 0;
    queue[rear++] = start_idx;
    
    printf("\nBFS Traversal from '%s':\n", start_username);
    printf("Level 0: %s\n", start_username);
    
    int current_level = 0;
    
    while (front < rear) {
        int level_size = rear - front;
        int next_level = current_level + 1;
        bool has_next_level = false;
        
        for (int i = 0; i < level_size; i++) {
            int current = queue[front++];
            GraphEdge* edge = graph->nodes[current].edges;
            
            while (edge) {
                int neighbor = edge->target_index;
                if (!graph->nodes[neighbor].visited) {
                    graph->nodes[neighbor].visited = true;
                    graph->nodes[neighbor].distance = next_level;
                    queue[rear++] = neighbor;
                    
                    if (!has_next_level) {
                        printf("Level %d:", next_level);
                        has_next_level = true;
                    }
                    printf(" %s", graph->nodes[neighbor].username);
                }
                edge = edge->next;
            }
        }
        
        if (has_next_level) {
            printf("\n");
            current_level = next_level;
        }
    }
    
    free(queue);
}

void graph_destroy(Graph* graph) {
    for (int i = 0; i < graph->num_nodes; i++) {
        GraphEdge* edge = graph->nodes[i].edges;
        while (edge) {
            GraphEdge* next = edge->next;
            free(edge);
            edge = next;
        }
    }
    free(graph->nodes);
    free(graph);
}

/*  CHARGEMENT CSV  */

int load_csv(const char* filename, LinkedList* list) {
    FILE* file = fopen(filename, "r");
    if (!file) {
        printf("Error: Cannot open file '%s'\n", filename);
        return 0;
    }
    
    char line[MAX_LINE];
    fgets(line, sizeof(line), file); // Skip header
    
    int count = 0;
    while (fgets(line, sizeof(line), file)) {
        LoginRecord record;
        char status[16];
        
        if (sscanf(line, "%31[^,],%63[^,],%31[^,],%15s",
                   record.timestamp, record.username, record.ip, status) == 4) {
            record.status = (strcmp(status, "SUCCESS") == 0) ? 
                           STATUS_SUCCESS : STATUS_FAILURE;
            
            ll_insert_tail(list, record);
            count++;
        }
    }
    
    fclose(file);
    printf("Loaded %d login records from '%s'\n", count, filename);
    return count;
}

/*  ANALYSE  */

void analyze_logins(LinkedList* list) {
    printf("\n=== ANALYZING LOGIN ATTEMPTS ===\n");
    
    Node* current = list->head;
    while (current) {
        LoginRecord* record = &current->data;
        
        // Trouver ou créer utilisateur
        int idx = findUser(record->username);
        if (idx == -1 && userCount < MAX_USERS) {
            idx = userCount;
            strcpy(users[idx].username, record->username);
            users[idx].total_attempts = 0;
            users[idx].failed_attempts = 0;
            users[idx].consecutive_failures = 0;
            users[idx].history = stack_create(STACK_SIZE);
            userCount++;
        }
        
        if (idx != -1) {
            users[idx].total_attempts++;
            if (record->status == STATUS_FAILURE) {
                users[idx].failed_attempts++;
            }
            
            // Push dans l'historique
            stack_push(users[idx].history, record->status);
            
            // Compter échecs consécutifs
            users[idx].consecutive_failures = 
                stack_count_consecutive_failures(users[idx].history);
            
            // Classifier
            users[idx].threat_level = classify_threat(users[idx].consecutive_failures);
        }
        
        current = current->next;
    }
    
    printf("Analysis complete. %d unique users found.\n", userCount);
}

/*  RAPPORTS  */

void print_suspicious_users() {
    printf("\n=== SUSPICIOUS USERS (Stack-based Detection) ===\n");
    int suspicious = 0;
    
    for (int i = 0; i < userCount; i++) {
        if (users[i].threat_level == SUSPICIOUS || users[i].threat_level == ATTACK) {
            const char* level = (users[i].threat_level == ATTACK) ? "ATTACK" : "SUSPICIOUS";
            printf("[%s] %s - %d consecutive failures, %d total failures\n",
                   level, users[i].username, 
                   users[i].consecutive_failures, users[i].failed_attempts);
            suspicious++;
        }
    }
    
    if (suspicious == 0) {
        printf("No suspicious users detected.\n");
    }
}

void compare_sorting_algorithms() {
    if (userCount == 0) {
        printf("No data to sort.\n");
        return;
    }
    
    printf("\n=== SORTING ALGORITHM COMPARISON ===\n");
    
    // Créer copies pour chaque algorithme
    UserStats* copy1 = (UserStats*)malloc(userCount * sizeof(UserStats));
    UserStats* copy2 = (UserStats*)malloc(userCount * sizeof(UserStats));
    UserStats* copy3 = (UserStats*)malloc(userCount * sizeof(UserStats));
    UserStats* copy4 = (UserStats*)malloc(userCount * sizeof(UserStats));
    
    for (int i = 0; i < userCount; i++) {
        copy1[i] = copy2[i] = copy3[i] = copy4[i] = users[i];
    }
    
    clock_t start, end;
    
    // Bubble Sort
    start = clock();
    bubble_sort(copy1, userCount);
    end = clock();
    double bubble_time = ((double)(end - start)) / CLOCKS_PER_SEC * 1000;
    
    // Insertion Sort
    start = clock();
    insertion_sort(copy2, userCount);
    end = clock();
    double insertion_time = ((double)(end - start)) / CLOCKS_PER_SEC * 1000;
    
    // Quick Sort
    start = clock();
    quick_sort(copy3, userCount);
    end = clock();
    double quick_time = ((double)(end - start)) / CLOCKS_PER_SEC * 1000;
    
    // Merge Sort
    start = clock();
    merge_sort(copy4, userCount);
    end = clock();
    double merge_time = ((double)(end - start)) / CLOCKS_PER_SEC * 1000;
    
    printf("Dataset size: %d users\n", userCount);
    printf("  Bubble Sort:    %.3f ms\n", bubble_time);
    printf("  Insertion Sort: %.3f ms\n", insertion_time);
    printf("  Quick Sort:     %.3f ms\n", quick_time);
    printf("  Merge Sort:     %.3f ms\n", merge_time);
    
    // Utiliser Quick Sort pour le reste
    for (int i = 0; i < userCount; i++) {
        users[i] = copy3[i];
    }
    
    free(copy1);
    free(copy2);
    free(copy3);
    free(copy4);
}

void build_and_analyze_graph(LinkedList* list) {
    printf("\n=== BUILDING ATTACK GRAPH ===\n");
    
    Graph* graph = graph_create(MAX_USERS);
    
    // Map IP -> liste d'utilisateurs
    typedef struct {
        char ip[MAX_IP];
        char users[50][MAX_USERNAME];
        int count;
    } IPMap;
    
    IPMap ip_map[200];
    int map_size = 0;
    
    Node* current = list->head;
    while (current) {
        if (current->data.status == STATUS_FAILURE) {
            // Trouver IP
            int ip_idx = -1;
            for (int i = 0; i < map_size; i++) {
                if (strcmp(ip_map[i].ip, current->data.ip) == 0) {
                    ip_idx = i;
                    break;
                }
            }
            
            if (ip_idx == -1 && map_size < 200) {
                ip_idx = map_size;
                strcpy(ip_map[ip_idx].ip, current->data.ip);
                ip_map[ip_idx].count = 0;
                map_size++;
            }
            
            if (ip_idx != -1) {
                // Ajouter utilisateur si pas déjà là
                bool found = false;
                for (int i = 0; i < ip_map[ip_idx].count; i++) {
                    if (strcmp(ip_map[ip_idx].users[i], current->data.username) == 0) {
                        found = true;
                        break;
                    }
                }
                
                if (!found && ip_map[ip_idx].count < 50) {
                    strcpy(ip_map[ip_idx].users[ip_map[ip_idx].count], current->data.username);
                    ip_map[ip_idx].count++;
                }
            }
        }
        current = current->next;
    }
    
    // Construire le graphe
    int attack_patterns = 0;
    for (int i = 0; i < map_size; i++) {
        if (ip_map[i].count >= 2) {
            attack_patterns++;
            
            // Ajouter sommets
            for (int j = 0; j < ip_map[i].count; j++) {
                graph_add_vertex(graph, ip_map[i].users[j]);
            }
            
            // Créer arêtes
            for (int j = 0; j < ip_map[i].count; j++) {
                for (int k = j + 1; k < ip_map[i].count; k++) {
                    graph_add_edge(graph, ip_map[i].users[j], 
                                 ip_map[i].users[k], ip_map[i].ip);
                    graph_add_edge(graph, ip_map[i].users[k], 
                                 ip_map[i].users[j], ip_map[i].ip);
                }
            }
        }
    }
    
    printf("Found %d attack patterns (IPs targeting multiple accounts)\n", attack_patterns);
    printf("Graph nodes: %d\n", graph->num_nodes);
    
    // BFS depuis le premier utilisateur suspect
    if (graph->num_nodes > 0) {
        graph_bfs(graph, graph->nodes[0].username);
    }
    
    graph_destroy(graph);
}

void build_classification_tree() {
    printf("\n=== BST CLASSIFICATION TREE ===\n");
    
    TreeNode* root = NULL;
    for (int i = 0; i < userCount; i++) {
        root = bst_insert(root, users[i].username, users[i].failed_attempts);
    }
    
    printf("\nATTACK Level (10+ failures):\n");
    bst_inorder_by_level(root, ATTACK);
    
    printf("\nSUSPICIOUS Level (3-9 failures):\n");
    bst_inorder_by_level(root, SUSPICIOUS);
    
    printf("\nNORMAL Level (0-2 failures):\n");
    bst_inorder_by_level(root, NORMAL);
    
    bst_destroy(root);
}

/*  MENU  */

void print_menu() {
    
    printf("       MALICIOUS LOGIN DETECTOR - COMPLETE             \n");
    
    printf("1. Load CSV File\n");
    printf("2. Analyze Logins (Stack-based Detection)\n");
    printf("3. Show Suspicious Users\n");
    printf("4. Compare Sorting Algorithms\n");
    printf("5. Show Top 10 Users by Failures\n");
    printf("6. Build Classification Tree (BST)\n");
    printf("7. Analyze Attack Graph (BFS/DFS)\n");
    printf("8. Run Complete Analysis\n");
    printf("0. Exit\n");
    printf("Choice: ");
}

/*  MAIN  */

int main() {
    LinkedList* login_list = NULL;
    bool data_loaded = false;
    
    int choice;
    do {
        print_menu();
        if (scanf("%d", &choice) != 1) {
            while (getchar() != '\n');
            continue;
        }
        
        switch (choice) {
            case 1: {
                printf("Enter CSV filename (default: logins.csv): ");
                char filename[256] = "logins.csv";
                scanf("%s", filename);
                
                if (login_list) {
                    ll_destroy(login_list);
                    for (int i = 0; i < userCount; i++) {
                        if (users[i].history) stack_destroy(users[i].history);
                    }
                    userCount = 0;
                }
                
                login_list = ll_create();
                if (load_csv(filename, login_list) > 0) {
                    data_loaded = true;
                }
                break;
            }
            
            case 2: {
                if (!data_loaded) {
                    printf("Please load CSV first!\n");
                    break;
                }
                analyze_logins(login_list);
                break;
            }
            
            case 3: {
                if (!data_loaded) {
                    printf("Please load CSV first!\n");
                    break;
                }
                print_suspicious_users();
                break;
            }
            
            case 4: {
                if (!data_loaded) {
                    printf("Please load CSV first!\n");
                    break;
                }
                compare_sorting_algorithms();
                break;
            }
            
            case 5: {
                if (!data_loaded) {
                    printf("Please load CSV first!\n");
                    break;
                }
                printf("\n=== TOP 10 USERS BY FAILURES ===\n");
                for (int i = 0; i < 10 && i < userCount; i++) {
                    printf("%2d. %-20s : %d failures (%d total attempts)\n",
                           i + 1, users[i].username, 
                           users[i].failed_attempts, users[i].total_attempts);
                }
                break;
            }
            
            case 6: {
                if (!data_loaded) {
                    printf("Please load CSV first!\n");
                    break;
                }
                build_classification_tree();
                break;
            }
            
            case 7: {
                if (!data_loaded) {
                    printf("Please load CSV first!\n");
                    break;
                }
                build_and_analyze_graph(login_list);
                break;
            }
            
            case 8: {
                if (!data_loaded) {
                    printf("Please load CSV first!\n");
                    break;
                }
                
                printf("            RUNNING COMPLETE ANALYSIS                    \n");
                
                
                analyze_logins(login_list);
                print_suspicious_users();
                compare_sorting_algorithms();
                
                printf("\n=== TOP 10 USERS BY FAILURES ===\n");
                for (int i = 0; i < 10 && i < userCount; i++) {
                    printf("%2d. %-20s : %d failures\n",
                           i + 1, users[i].username, users[i].failed_attempts);
                }
                
                build_classification_tree();
                build_and_analyze_graph(login_list);
                
                printf("\n✓ Complete analysis finished!\n");
                break;
            }
            
            case 0:
                printf("Exiting...\n");
                break;
                
            default:
                printf("Invalid choice!\n");
        }
        
    } while (choice != 0);
    
    // Cleanup
    if (login_list) {
        ll_destroy(login_list);
    }
    for (int i = 0; i < userCount; i++) {
        if (users[i].history) {
            stack_destroy(users[i].history);
        }
    }
    
    return 0;
}