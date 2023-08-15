#include<stdio.h>
#include<conio.h>
#include<string.h>
void main()
{
      char msg[100];
      char key[100],k[100],ciphertext[100],plaintext[100];
      int lenm,lenk;
      //clrscr();

      printf("Enter Message : ");
      gets(msg);
      printf("Enter Key : ");
      gets(key);
      lenm=strlen(msg);
      lenk=strlen(key);
      int i,j;
      for( i=0;i<lenm;i++,j++)
      {
            if(j==lenk)
            {
                  j=0;
            }
            k[i]=key[j];
      }
      for( i=0;i<lenm;i++)
      {
            ciphertext[i]=((msg[i]+k[i])%26)+'A';
      }
      ciphertext[i]='\0';
      for(i=0;i<lenm;i++)
      {
            plaintext[i]=(((ciphertext[i]-k[i])+26)%26)+'A';
      }
      plaintext[i]='\0';
      printf("\nEncrypted Message : %s", ciphertext);
      printf("\nDecrypted Message : %s", plaintext);
      getch();
}
