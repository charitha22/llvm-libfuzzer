// C program for insertion sort
#include <stdio.h>
#include <math.h>
int comps = 0;
#define SIZE 100
/* Function to sort an array using insertion sort*/
void insertionSort(int arr[], int n)
{
   int i, key, j;
   for (i = 1; i < n; i++)
   {
       key = arr[i];
       j = i-1;
 
       /* Move elements of arr[0..i-1], that are
          greater than key, to one position ahead
          of their current position */
       while (j >= 0 && arr[j] > key)
       {
           comps ++;
           arr[j+1] = arr[j];
           j = j-1;
       }
       arr[j+1] = key;
   }
}
 
// A utility function ot print an array of size n
void printArray(int arr[], int n)
{
   int i;
   for (i=0; i < n; i++)
       printf("%d ", arr[i]);
   printf("\n");
}
 
 
 
/* Driver program to test insertion sort */
int isort_driver(const uint8_t * data, size_t size)
{
    if(size!=SIZE) return -1;
    
    comps = 0;

    printf("size of data = %zu\n", size);
    int i = 0;
    int sortarray[size]; 
    
    while (i < size) {
       sortarray[i]= (int) *(data++);
       i++;
    } 

    printArray(sortarray, size);
    insertionSort(sortarray, size);
    printArray(sortarray, size);
    printf("comps: %d\n", comps);

    //if (comps == 10*19) {
       //return 1;
    //}
    return 0;
}

