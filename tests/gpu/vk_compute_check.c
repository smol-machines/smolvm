// Minimal Vulkan compute end-to-end test: allocate a storage buffer, dispatch a
// shader that writes a known pattern, read it back on the host, verify.
// Proves the whole path -- instance, device, memory, queue, dispatch, readback --
// not merely that a device can be enumerated.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <vulkan/vulkan.h>
#define N 1024
#define CK(x,msg) do{VkResult r=(x); if(r!=VK_SUCCESS){printf("FAIL %s: %d\n",msg,r);return 1;}}while(0)
int main(void){
  VkApplicationInfo ai={.sType=VK_STRUCTURE_TYPE_APPLICATION_INFO,.apiVersion=VK_API_VERSION_1_1};
  VkInstanceCreateInfo ici={.sType=VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO,.pApplicationInfo=&ai};
  VkInstance inst; CK(vkCreateInstance(&ici,0,&inst),"vkCreateInstance");
  uint32_t n=0; vkEnumeratePhysicalDevices(inst,&n,0);
  if(!n){printf("FAIL: no physical device\n");return 1;}
  VkPhysicalDevice *pds=malloc(n*sizeof(*pds)); vkEnumeratePhysicalDevices(inst,&n,pds);
  VkPhysicalDevice pd=pds[0];
  VkPhysicalDeviceProperties props; vkGetPhysicalDeviceProperties(pd,&props);
  printf("device: %s (driver %u.%u.%u)\n",props.deviceName,
     VK_VERSION_MAJOR(props.driverVersion),VK_VERSION_MINOR(props.driverVersion),VK_VERSION_PATCH(props.driverVersion));
  uint32_t qn=0; vkGetPhysicalDeviceQueueFamilyProperties(pd,&qn,0);
  VkQueueFamilyProperties *qs=malloc(qn*sizeof(*qs)); vkGetPhysicalDeviceQueueFamilyProperties(pd,&qn,qs);
  uint32_t qi=UINT32_MAX; for(uint32_t i=0;i<qn;i++) if(qs[i].queueFlags&VK_QUEUE_COMPUTE_BIT){qi=i;break;}
  if(qi==UINT32_MAX){printf("FAIL: no compute queue\n");return 1;}
  float prio=1.0f;
  VkDeviceQueueCreateInfo qci={.sType=VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO,.queueFamilyIndex=qi,.queueCount=1,.pQueuePriorities=&prio};
  VkDeviceCreateInfo dci={.sType=VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO,.queueCreateInfoCount=1,.pQueueCreateInfos=&qci};
  VkDevice dev; CK(vkCreateDevice(pd,&dci,0,&dev),"vkCreateDevice");
  VkQueue q; vkGetDeviceQueue(dev,qi,0,&q);
  VkBufferCreateInfo bci={.sType=VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO,.size=N*sizeof(uint32_t),
    .usage=VK_BUFFER_USAGE_STORAGE_BUFFER_BIT,.sharingMode=VK_SHARING_MODE_EXCLUSIVE};
  VkBuffer buf; CK(vkCreateBuffer(dev,&bci,0,&buf),"vkCreateBuffer");
  VkMemoryRequirements mr; vkGetBufferMemoryRequirements(dev,buf,&mr);
  VkPhysicalDeviceMemoryProperties mp; vkGetPhysicalDeviceMemoryProperties(pd,&mp);
  uint32_t mi=UINT32_MAX;
  for(uint32_t i=0;i<mp.memoryTypeCount;i++){
    VkMemoryPropertyFlags f=mp.memoryTypes[i].propertyFlags;
    if((mr.memoryTypeBits&(1u<<i))&&(f&VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT)&&(f&VK_MEMORY_PROPERTY_HOST_COHERENT_BIT)){mi=i;break;}
  }
  if(mi==UINT32_MAX){printf("FAIL: no host-visible memory type\n");return 1;}
  VkMemoryAllocateInfo mai={.sType=VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO,.allocationSize=mr.size,.memoryTypeIndex=mi};
  VkDeviceMemory mem; CK(vkAllocateMemory(dev,&mai,0,&mem),"vkAllocateMemory");
  CK(vkBindBufferMemory(dev,buf,mem,0),"vkBindBufferMemory");
  FILE*f=fopen(getenv("VK_COMPUTE_SPV") ? getenv("VK_COMPUTE_SPV") : "/tmp/comp.spv","rb"); if(!f){printf("FAIL: no spv\n");return 1;}
  fseek(f,0,SEEK_END); long sz=ftell(f); fseek(f,0,SEEK_SET);
  uint32_t*code=malloc(sz); if(fread(code,1,sz,f)!=(size_t)sz){printf("FAIL: spv read\n");return 1;} fclose(f);
  VkShaderModuleCreateInfo smci={.sType=VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO,.codeSize=sz,.pCode=code};
  VkShaderModule sm; CK(vkCreateShaderModule(dev,&smci,0,&sm),"vkCreateShaderModule");
  VkDescriptorSetLayoutBinding b={.binding=0,.descriptorType=VK_DESCRIPTOR_TYPE_STORAGE_BUFFER,.descriptorCount=1,.stageFlags=VK_SHADER_STAGE_COMPUTE_BIT};
  VkDescriptorSetLayoutCreateInfo dlci={.sType=VK_STRUCTURE_TYPE_DESCRIPTOR_SET_LAYOUT_CREATE_INFO,.bindingCount=1,.pBindings=&b};
  VkDescriptorSetLayout dsl; CK(vkCreateDescriptorSetLayout(dev,&dlci,0,&dsl),"dsl");
  VkPipelineLayoutCreateInfo plci={.sType=VK_STRUCTURE_TYPE_PIPELINE_LAYOUT_CREATE_INFO,.setLayoutCount=1,.pSetLayouts=&dsl};
  VkPipelineLayout pl; CK(vkCreatePipelineLayout(dev,&plci,0,&pl),"pl");
  VkComputePipelineCreateInfo cpci={.sType=VK_STRUCTURE_TYPE_COMPUTE_PIPELINE_CREATE_INFO,
    .stage={.sType=VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO,.stage=VK_SHADER_STAGE_COMPUTE_BIT,.module=sm,.pName="main"},.layout=pl};
  VkPipeline pipe; CK(vkCreateComputePipelines(dev,VK_NULL_HANDLE,1,&cpci,0,&pipe),"pipeline");
  VkDescriptorPoolSize ps={.type=VK_DESCRIPTOR_TYPE_STORAGE_BUFFER,.descriptorCount=1};
  VkDescriptorPoolCreateInfo dpci={.sType=VK_STRUCTURE_TYPE_DESCRIPTOR_POOL_CREATE_INFO,.maxSets=1,.poolSizeCount=1,.pPoolSizes=&ps};
  VkDescriptorPool dp; CK(vkCreateDescriptorPool(dev,&dpci,0,&dp),"pool");
  VkDescriptorSetAllocateInfo dsai={.sType=VK_STRUCTURE_TYPE_DESCRIPTOR_SET_ALLOCATE_INFO,.descriptorPool=dp,.descriptorSetCount=1,.pSetLayouts=&dsl};
  VkDescriptorSet ds; CK(vkAllocateDescriptorSets(dev,&dsai,&ds),"ds");
  VkDescriptorBufferInfo dbi={.buffer=buf,.offset=0,.range=VK_WHOLE_SIZE};
  VkWriteDescriptorSet w={.sType=VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET,.dstSet=ds,.dstBinding=0,.descriptorCount=1,
    .descriptorType=VK_DESCRIPTOR_TYPE_STORAGE_BUFFER,.pBufferInfo=&dbi};
  vkUpdateDescriptorSets(dev,1,&w,0,0);
  VkCommandPoolCreateInfo cpci2={.sType=VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO,.queueFamilyIndex=qi};
  VkCommandPool cp; CK(vkCreateCommandPool(dev,&cpci2,0,&cp),"cmdpool");
  VkCommandBufferAllocateInfo cbai={.sType=VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO,.commandPool=cp,.level=VK_COMMAND_BUFFER_LEVEL_PRIMARY,.commandBufferCount=1};
  VkCommandBuffer cb; CK(vkAllocateCommandBuffers(dev,&cbai,&cb),"cmdbuf");
  VkCommandBufferBeginInfo bi={.sType=VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO,.flags=VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT};
  CK(vkBeginCommandBuffer(cb,&bi),"begin");
  vkCmdBindPipeline(cb,VK_PIPELINE_BIND_POINT_COMPUTE,pipe);
  vkCmdBindDescriptorSets(cb,VK_PIPELINE_BIND_POINT_COMPUTE,pl,0,1,&ds,0,0);
  vkCmdDispatch(cb,N/64,1,1);
  CK(vkEndCommandBuffer(cb),"end");
  VkSubmitInfo si={.sType=VK_STRUCTURE_TYPE_SUBMIT_INFO,.commandBufferCount=1,.pCommandBuffers=&cb};
  CK(vkQueueSubmit(q,1,&si,VK_NULL_HANDLE),"submit");
  CK(vkQueueWaitIdle(q),"waitidle");
  void*map; CK(vkMapMemory(dev,mem,0,VK_WHOLE_SIZE,0,&map),"map");
  uint32_t*out=map; int bad=0;
  for(uint32_t i=0;i<N;i++) if(out[i]!=i*3u+7u){ if(!bad) printf("first mismatch at %u: got %u want %u\n",i,out[i],i*3u+7u); bad++; }
  printf(bad? "COMPUTE FAILED: %d/%d wrong\n" : "COMPUTE OK: all %d values correct (GPU wrote them)\n", bad?bad:N, N);
  return bad?1:0;
}
